import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import backdooredTipJar from '../../fixtures/backdoored_tip_jar/contract.py?raw'
import App, { canonicalizeSource, pinnedSourceUrl, reportSha256, sourceSha256 } from './App'
import type { AnalyzeResponse, AuditReport } from './types'

const IMPLEMENTED_RULES = [
  'AUTH-01', 'BOUND-01', 'CONS-01', 'EVID-01', 'PROMPT-01', 'REPLAY-01',
  'RESULT-01', 'SRC-01', 'STATE-01', 'TIME-01', 'URL-01', 'VALUE-01',
]
const TIP_JAR_URL = 'https://raw.githubusercontent.com/horn111/equivlab/aef703943cef6a6d9c3f65545072711d78d44417/fixtures/backdoored_tip_jar/contract.py'

async function makeFailResponse(
  overrides: Partial<AuditReport> = {},
  sourceMode: AnalyzeResponse['source_mode'] = 'retrieved',
): Promise<AnalyzeResponse> {
  const base: AuditReport = {
    failed_rules: ['AUTH-01', 'VALUE-01'],
    findings: [
      {
        evidence: [{ detail: 'Unguarded transfer path: withdraw_to', line: 23, symbol: 'TipJar.withdraw_to' }],
        rule: 'AUTH-01',
        severity: 'CRITICAL',
        status: 'FAIL',
        summary: 'A public value-transfer path has no preceding caller-derived authority guard.',
      },
      {
        evidence: [{ detail: 'unguarded transfer recipient depends on caller input', line: 25, symbol: 'TipJar.withdraw_to' }],
        rule: 'VALUE-01',
        severity: 'CRITICAL',
        status: 'FAIL',
        summary: 'A public transfer path lets caller input control material value-transfer fields.',
      },
      {
        evidence: [{ detail: 'Public write entrypoint has no reachable GenLayer consensus call.', line: 20, symbol: 'TipJar.withdraw_to' }],
        rule: 'CONS-01',
        severity: 'CRITICAL',
        status: 'UNVERIFIABLE',
        summary: 'A GenLayer contract was found, but no run_nondet_unsafe consensus path is reachable from a public write entrypoint.',
      },
    ],
    implemented_rules: IMPLEMENTED_RULES,
    policy: 'gl-consensus-baseline-3',
    report_sha256: '0'.repeat(64),
    schema: 'equivlab-report-v2',
    severity: 'CRITICAL',
    scope: 'Twelve deterministic rule cores only.',
    source: { canonical_sha256: await sourceSha256(backdooredTipJar), mode: sourceMode, url: TIP_JAR_URL },
    status: 'FAIL',
    unverifiable_rules: ['CONS-01'],
    warning_rules: [],
  }
  const report: AuditReport = {
    ...base,
    ...overrides,
    source: { ...base.source, ...overrides.source },
  }
  report.report_sha256 = await reportSha256(report)
  return { source_mode: sourceMode, report }
}

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.unstubAllEnvs()
  localStorage.clear()
  window.history.replaceState(null, '', '/')
  delete window.ethereum
})

describe('source identity helpers', () => {
  it('normalizes BOM, newlines, and the final newline', () => {
    expect(canonicalizeSource('\ufeffa\r\nb\rc')).toBe('a\nb\nc\n')
  })

  it('builds an exact raw GitHub URL from repository coordinates', () => {
    expect(pinnedSourceUrl({ repository: 'https://github.com/acme/contracts.git', commit: '1'.repeat(40), path: '/src/contract.py' }))
      .toBe(`https://raw.githubusercontent.com/acme/contracts/${'1'.repeat(40)}/src/contract.py`)
  })
})

describe('EquivLab workbench', () => {
  it('shows rail selection feedback in the visible rule spectrum before analysis', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.click(screen.getByTitle('Inspect CONS-01'))
    const focus = screen.getByRole('status', { name: 'Selected rule' })
    expect(within(focus).getByText('CONS-01')).toBeInTheDocument()
    expect(within(focus).getByText('GenLayer consensus eligibility')).toBeInTheDocument()
    expect(within(focus).getByText('UNREAD')).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: 'Rule spectrum' })).not.toBeInTheDocument()
  })

  it('discards legacy identity-less archive records instead of rendering them', async () => {
    const failResponse = await makeFailResponse()
    localStorage.setItem('equivlab:history:v2', JSON.stringify([{ id: 'legacy', label: 'Legacy', report: failResponse.report }]))
    render(<App />)

    expect(screen.queryByText('Legacy')).not.toBeInTheDocument()
  })

  it('rejects a shared report whose source URL does not match its pinned identity', async () => {
    const failResponse = await makeFailResponse()
    const tampered = {
      fixtureId: 'tip-jar',
      identity: {
        repository: 'horn111/equivlab',
        commit: 'aef703943cef6a6d9c3f65545072711d78d44417',
        path: 'fixtures/backdoored_tip_jar/contract.py',
        source: 'contract source',
      },
      report: { ...failResponse.report, source: { ...failResponse.report.source, url: 'https://example.invalid/tampered.py' } },
      sourceMode: 'submitted',
      version: 1,
    }
    const encoded = btoa(JSON.stringify(tampered)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
    window.history.replaceState(null, '', `/#r=${encoded}`)
    render(<App />)

    expect(screen.queryByText(/no preceding caller-derived authority guard/i)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /run analysis to share/i })).toBeDisabled()
  })

  it('keeps local findings available before any wallet connection', async () => {
    const user = userEvent.setup()
    const failResponse = await makeFailResponse()
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => failResponse })
    vi.stubGlobal('fetch', fetchMock)
    render(<App />)

    const analyzeButton = await screen.findByRole('button', { name: /analyze revision/i })
    await waitFor(() => expect(analyzeButton).toBeEnabled())
    await user.click(analyzeButton)

    const requestBody = JSON.parse(String(fetchMock.mock.calls[0][1]?.body)) as Record<string, unknown>
    expect(requestBody).not.toHaveProperty('source')
    expect(screen.getByRole('checkbox', { name: /analyze editor preview instead/i })).not.toBeChecked()
    expect((await screen.findAllByText(/no preceding caller-derived authority guard/i)).length).toBeGreaterThan(0)
    expect(screen.getAllByText('AUTH-01').length).toBeGreaterThan(0)
    expect(screen.getAllByText('VALUE-01').length).toBeGreaterThan(0)
    expect(screen.queryByRole('button', { name: /request attestation/i })).not.toBeInTheDocument()
    expect(await screen.findByRole('heading', { name: /registry boundary/i })).toBeInTheDocument()
    expect(screen.getByLabelText('Local analysis result: FAIL')).toHaveFocus()
    expect(screen.getAllByRole('button', { name: /reproduce analysis/i })).toHaveLength(2)
    expect(screen.getByRole('button', { name: /reveal pinned raw url/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /copy canonical sha-256/i })).toBeInTheDocument()
  })

  it('reproduces a bundled preview from the pinned source without dropping the connected wallet', async () => {
    const user = userEvent.setup()
    const submitted = await makeFailResponse({}, 'submitted')
    const retrieved = await makeFailResponse({}, 'retrieved')
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: async () => submitted })
      .mockResolvedValueOnce({ ok: true, json: async () => retrieved })
    vi.stubGlobal('fetch', fetchMock)
    vi.stubEnv('VITE_NETWORK_NAME', 'testnetBradbury')
    vi.stubEnv('VITE_REGISTRY_ADDRESS', `0x${'2'.repeat(40)}`)
    const address = `0x${'1'.repeat(40)}`
    window.ethereum = {
      request: vi.fn(async ({ method }) => {
        if (method === 'eth_requestAccounts') return [address]
        if (method === 'eth_chainId') return '0x107d'
        return null
      }),
    }
    render(<App />)

    await user.click(screen.getByRole('checkbox', { name: /analyze editor preview instead/i }))
    const analyzeButton = await screen.findByRole('button', { name: /analyze revision/i })
    await waitFor(() => expect(analyzeButton).toBeEnabled())
    await user.click(analyzeButton)
    await user.click(await screen.findByRole('button', { name: /connect wallet/i }))
    await user.click(screen.getByRole('button', { name: /retrieve pinned source/i }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
    const secondBody = JSON.parse(String(fetchMock.mock.calls[1][1]?.body)) as Record<string, unknown>
    expect(secondBody).not.toHaveProperty('source')
    expect(await screen.findByText('Retrieve pinned revision')).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: /analyze editor preview instead/i })).not.toBeChecked()
    expect(screen.getByTitle(address)).toBeInTheDocument()
  })

  it('invalidates a report when the visible source identity changes', async () => {
    const user = userEvent.setup()
    const failResponse = await makeFailResponse()
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => failResponse }))
    render(<App />)
    const analyzeButton = await screen.findByRole('button', { name: /analyze revision/i })
    await waitFor(() => expect(analyzeButton).toBeEnabled())
    await user.click(analyzeButton)
    expect((await screen.findAllByText(/no preceding caller-derived authority guard/i)).length).toBeGreaterThan(0)

    await user.clear(screen.getByRole('textbox', { name: 'Repository' }))
    await user.type(screen.getByRole('textbox', { name: 'Repository' }), 'equivlab/changed')

    expect(screen.queryAllByText(/no preceding caller-derived authority guard/i)).toHaveLength(0)
    expect(screen.getByRole('button', { name: /run analysis to share/i })).toBeDisabled()
  })

  it('restores a shared report only as an unverified snapshot pending reproduction', async () => {
    const user = userEvent.setup()
    const failResponse = await makeFailResponse()
    const writeText = vi.fn()
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => failResponse }))
    render(<App />)
    const analyzeButton = await screen.findByRole('button', { name: /analyze revision/i })
    await waitFor(() => expect(analyzeButton).toBeEnabled())
    await user.click(analyzeButton)
    await screen.findAllByText(/no preceding caller-derived authority guard/i)
    await user.click(screen.getByRole('button', { name: 'Share snapshot' }))

    const sharedUrl = writeText.mock.calls[0][0] as string
    expect(sharedUrl).toContain('#r=')
    cleanup()
    const shared = new URL(sharedUrl)
    window.history.replaceState(null, '', `${shared.pathname}${shared.search}${shared.hash}`)
    render(<App />)

    expect(screen.queryByText(/no preceding caller-derived authority guard/i)).not.toBeInTheDocument()
    expect(screen.getByText('Unverified local snapshot')).toBeInTheDocument()
    expect(screen.getByText(/run analysis to reproduce its findings/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /run analysis to share/i })).toBeDisabled()
  })

  it('rejects analyzer reports that omit implemented policy rules', async () => {
    const user = userEvent.setup()
    const incomplete = await makeFailResponse({ implemented_rules: ['AUTH-01', 'VALUE-01'] })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => incomplete }))
    render(<App />)

    const analyzeButton = await screen.findByRole('button', { name: /analyze revision/i })
    await waitFor(() => expect(analyzeButton).toBeEnabled())
    await user.click(analyzeButton)

    expect(await screen.findByRole('alert')).toHaveTextContent(/could not be reproduced/i)
    expect(screen.queryByText(/no preceding caller-derived authority guard/i)).not.toBeInTheDocument()
  })

  it('surfaces a compact analyzer support reference without exposing internals', async () => {
    const user = userEvent.setup()
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 429,
      json: async () => ({ error: 'Rate limit reached. Retry shortly.', request_id: 'req_4f9c2a' }),
    }))
    render(<App />)

    const analyzeButton = await screen.findByRole('button', { name: /analyze revision/i })
    await waitFor(() => expect(analyzeButton).toBeEnabled())
    await user.click(analyzeButton)

    expect(await screen.findByRole('alert')).toHaveTextContent('Rate limit reached. Retry shortly. Support reference: req_4f9c2a.')
  })

  it('disables analysis immediately while a changed source digest is pending', async () => {
    const user = userEvent.setup()
    render(<App />)
    const analyzeButton = await screen.findByRole('button', { name: /analyze revision/i })
    await waitFor(() => expect(analyzeButton).toBeEnabled())

    await user.type(screen.getByRole('textbox', { name: 'Contract source preview' }), '\n# changed')
    expect(analyzeButton).toBeDisabled()
    await waitFor(() => expect(analyzeButton).toBeEnabled())
  })

  it('does not expose wallet connection before registry configuration', async () => {
    render(<App />)

    expect(screen.queryByRole('button', { name: /connect wallet/i })).not.toBeInTheDocument()
  })

  it('exposes all four honest result classes in the reference workflow', () => {
    render(<App />)
    expect(screen.getByRole('button', { name: /permissionless tip jar/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /schema-only validator/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /hardened fact checker/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /plain python file/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /hash mismatch/i })).toBeInTheDocument()
  })
})
