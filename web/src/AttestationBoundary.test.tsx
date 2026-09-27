import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { TransactionHash } from 'genlayer-js/types'
import AttestationBoundary from './AttestationBoundary'
import type { AuditReport, OnChainReadback } from './types'

const ADDRESS = `0x${'1'.repeat(40)}` as const
const REGISTRY = `0x${'2'.repeat(40)}` as const
const OVERLAY = `0x${'8'.repeat(40)}` as const
const TX_HASH = `0x${'3'.repeat(64)}` as TransactionHash
const SOURCE_HASH = '4'.repeat(64)
const SOURCE_URL = `https://raw.githubusercontent.com/equivlab/demo/${'5'.repeat(40)}/fixtures/backdoored_tip_jar/contract.py`
const onEditSourceRevision = vi.fn()
const onUsePinnedSource = vi.fn()

const mocks = vi.hoisted(() => ({
  overlayAddress: null as string | null,
  ensureWalletNetwork: vi.fn(),
  writeContract: vi.fn(),
  waitForTransactionReceipt: vi.fn(),
  readAuthoritativeAudit: vi.fn(),
  readLatestRegistryAudit: vi.fn(),
}))

vi.mock('./genlayer', () => ({
  createGenLayerReadClient: () => ({ waitForTransactionReceipt: mocks.waitForTransactionReceipt }),
  createGenLayerWriteClient: () => ({ writeContract: mocks.writeContract }),
  ensureWalletNetwork: mocks.ensureWalletNetwork,
  isSuccessfulExecution: (receipt: { txExecutionResultName?: string }) => receipt.txExecutionResultName === 'FINISHED_WITH_RETURN',
  isUndeterminedReceipt: (receipt: { statusName?: string }) => receipt.statusName === 'UNDETERMINED',
  readAuthoritativeAudit: mocks.readAuthoritativeAudit,
  readLatestRegistryAudit: mocks.readLatestRegistryAudit,
  resolveGenLayerConfig: () => ({
    config: {
      explorerBaseUrl: 'https://explorer-bradbury.genlayer.com',
      network: 'testnetBradbury',
      registryAddress: REGISTRY,
      ...(mocks.overlayAddress ? { promptOverlayAddress: mocks.overlayAddress } : {}),
    },
    error: null,
  }),
  transactionExplorerUrl: (_config: unknown, hash: string) => `https://explorer-bradbury.genlayer.com/tx/${hash}`,
  walletErrorMessage: (error: unknown, fallback: string) => error && typeof error === 'object' && 'message' in error
    ? String(error.message)
    : fallback,
}))

const report: AuditReport = {
  failed_rules: ['AUTH-01', 'VALUE-01'],
  findings: [],
  implemented_rules: ['AUTH-01', 'VALUE-01'],
  policy: 'gl-consensus-baseline-3',
  report_sha256: '6'.repeat(64),
  schema: 'equivlab-report-v2',
  severity: 'CRITICAL',
  scope: 'Test report.',
  source: { canonical_sha256: SOURCE_HASH, mode: 'retrieved', url: SOURCE_URL },
  status: 'FAIL',
  unverifiable_rules: [],
  warning_rules: [],
}

const authoritative: OnChainReadback = {
  audit: {
    challenged: false,
    created_at: '2026-08-25T00:00:00Z',
    id: '7',
    policy: report.policy,
    requester: ADDRESS,
    source_hash: SOURCE_HASH,
    source_url: SOURCE_URL,
    status: 'FAIL',
    superseded_by: null,
    supersedes_id: null,
  },
  report,
  transactionHash: TX_HASH,
}

afterEach(() => {
  cleanup()
  localStorage.clear()
  vi.clearAllMocks()
  mocks.overlayAddress = null
  delete window.ethereum
})

describe('attestation lifecycle', () => {
  it('shows an existing consensus correction without asking for a duplicate wallet transaction', async () => {
    mocks.overlayAddress = OVERLAY
    const localPrompt: AuditReport = {
      ...report, failed_rules: [], findings: [], implemented_rules: ['PROMPT-01'],
      report_sha256: 'a'.repeat(64), severity: 'LOW', status: 'MEETS_BASELINE',
    }
    const baseReport: AuditReport = {
      ...localPrompt, failed_rules: ['PROMPT-01'], report_sha256: 'b'.repeat(64),
      severity: 'HIGH', status: 'FAIL',
    }
    mocks.readLatestRegistryAudit.mockResolvedValueOnce({
      ...authoritative,
      audit: { ...authoritative.audit, status: 'FAIL' },
      report: localPrompt,
      baseReport,
      promptOverlay: {
        audit_id: '7', base_registry: REGISTRY, base_report_sha256: baseReport.report_sha256,
        created_at: '2026-09-27T00:00:00Z', outcome: 'MEETS_BASELINE',
        report_sha256: localPrompt.report_sha256, source_hash: SOURCE_HASH, source_url: SOURCE_URL,
      },
    } satisfies OnChainReadback)

    render(<AttestationBoundary analysisLoading={false} report={localPrompt} sourceMode="retrieved" onEditSourceRevision={onEditSourceRevision} onUsePinnedSource={onUsePinnedSource} />)
    expect(await screen.findByRole('region', { name: /consensus-corrected readback/i })).toBeInTheDocument()
    expect(screen.getByText(/original registry report remains unchanged/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /reconcile prompt-01 onchain/i })).not.toBeInTheDocument()
  })

  it('reconciles only PROMPT-01 through a separate finalized GenLayer transaction', async () => {
    const user = userEvent.setup()
    mocks.overlayAddress = OVERLAY
    const localPrompt: AuditReport = {
      ...report, failed_rules: [], findings: [], implemented_rules: ['PROMPT-01'],
      report_sha256: 'a'.repeat(64), severity: 'LOW', status: 'MEETS_BASELINE',
    }
    const baseReport: AuditReport = {
      ...localPrompt, failed_rules: ['PROMPT-01'], report_sha256: 'b'.repeat(64),
      severity: 'HIGH', status: 'FAIL',
    }
    const baseReadback: OnChainReadback = {
      ...authoritative, audit: { ...authoritative.audit, status: 'FAIL' }, report: baseReport,
    }
    const correctedReadback: OnChainReadback = {
      ...baseReadback, report: localPrompt, baseReport,
      promptOverlay: {
        audit_id: '7', base_registry: REGISTRY, base_report_sha256: baseReport.report_sha256,
        created_at: '2026-09-27T00:00:00Z', outcome: 'MEETS_BASELINE',
        report_sha256: localPrompt.report_sha256, source_hash: SOURCE_HASH, source_url: SOURCE_URL,
      },
    }
    mocks.readLatestRegistryAudit.mockResolvedValueOnce(baseReadback).mockResolvedValueOnce(correctedReadback)
    mocks.writeContract.mockResolvedValue(TX_HASH)
    mocks.waitForTransactionReceipt.mockResolvedValue({ statusName: 'FINALIZED', txExecutionResultName: 'FINISHED_WITH_RETURN' })
    window.ethereum = { request: vi.fn().mockResolvedValue([ADDRESS]) }

    render(<AttestationBoundary analysisLoading={false} report={localPrompt} sourceMode="retrieved" onEditSourceRevision={onEditSourceRevision} onUsePinnedSource={onUsePinnedSource} />)
    await user.click(await screen.findByRole('button', { name: /connect wallet to reconcile prompt-01/i }))
    await user.click(await screen.findByRole('button', { name: /reconcile prompt-01 onchain/i }))

    expect(await screen.findByRole('region', { name: /consensus-corrected readback/i })).toBeInTheDocument()
    expect(screen.getByText(/original registry report remains unchanged/i)).toBeInTheDocument()
    expect(mocks.writeContract).toHaveBeenCalledWith({
      address: OVERLAY, functionName: 'reconcile', args: [7n], value: 0n,
    })
    expect(localStorage.getItem('equivlab:pending-prompt-overlay:v1')).toBeNull()
  })
  it('claims authority only after a successful finalized receipt and source-matched readback', async () => {
    const user = userEvent.setup()
    window.ethereum = { request: vi.fn().mockResolvedValue([ADDRESS]) }
    mocks.writeContract.mockResolvedValue(TX_HASH)
    mocks.waitForTransactionReceipt
      .mockResolvedValueOnce({ statusName: 'ACCEPTED', txExecutionResultName: 'FINISHED_WITH_RETURN' })
      .mockResolvedValueOnce({ statusName: 'FINALIZED', txExecutionResultName: 'FINISHED_WITH_RETURN' })
    mocks.readAuthoritativeAudit.mockResolvedValue(authoritative)
    mocks.readLatestRegistryAudit.mockResolvedValue(null)

    render(<AttestationBoundary analysisLoading={false} report={report} sourceMode="retrieved" onEditSourceRevision={onEditSourceRevision} onUsePinnedSource={onUsePinnedSource} />)
    await user.click(screen.getByRole('button', { name: /connect wallet/i }))
    expect(mocks.ensureWalletNetwork).toHaveBeenCalledWith(
      expect.objectContaining({ network: 'testnetBradbury' }),
      window.ethereum,
    )
    expect(mocks.writeContract).not.toHaveBeenCalled()
    await user.click(await screen.findByRole('button', { name: /request genlayer review/i }))

    expect(await screen.findByRole('region', { name: /authoritative registry readback/i })).toBeInTheDocument()
    expect(screen.getByText('7')).toBeInTheDocument()
    expect(mocks.writeContract).toHaveBeenCalledWith({
      address: REGISTRY,
      functionName: 'request_audit',
      args: [SOURCE_URL, SOURCE_HASH, report.policy],
      value: 0n,
    })
    await waitFor(() => expect(mocks.readAuthoritativeAudit).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ registryAddress: REGISTRY }),
      SOURCE_HASH,
      SOURCE_URL,
      report.policy,
      TX_HASH,
    ))
    expect(localStorage.getItem('equivlab:pending-attestation:v1')).toBeNull()
  })

  it('loads an existing source-matched audit without wallet state on a fresh browser', async () => {
    const user = userEvent.setup()
    mocks.readLatestRegistryAudit.mockResolvedValue(authoritative)

    render(<AttestationBoundary analysisLoading={false} report={report} sourceMode="retrieved" onEditSourceRevision={onEditSourceRevision} onUsePinnedSource={onUsePinnedSource} />)

    expect(await screen.findByRole('region', { name: /existing registry readback/i })).toBeInTheDocument()
    expect(screen.getByText(/already registered/i)).toBeInTheDocument()
    expect(screen.getByText('Local and registry report hashes match')).toBeInTheDocument()
    expect(screen.getAllByText(/finalization was not independently checked/i).length).toBeGreaterThan(0)
    expect(screen.queryByRole('button', { name: /request genlayer review/i })).not.toBeInTheDocument()
    expect(screen.getByText(/to trigger a new review/i)).toBeInTheDocument()
    window.ethereum = { request: vi.fn().mockResolvedValue([ADDRESS]) }
    await user.click(screen.getByRole('button', { name: /connect wallet to challenge/i }))
    expect(screen.queryByRole('button', { name: /request genlayer review/i })).not.toBeInTheDocument()
    expect(mocks.writeContract).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: /analyze a new revision/i }))
    expect(onEditSourceRevision).toHaveBeenCalledOnce()
    expect(mocks.readLatestRegistryAudit).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ registryAddress: REGISTRY }),
      SOURCE_HASH,
      SOURCE_URL,
      report.policy,
    )
  })

  it('explains different report hashes when the rule outcomes agree regardless of array order', async () => {
    mocks.readLatestRegistryAudit.mockResolvedValue({
      ...authoritative,
      report: { ...report, report_sha256: 'a'.repeat(64), failed_rules: [...report.failed_rules].reverse() },
    })
    render(<AttestationBoundary analysisLoading={false} report={report} sourceMode="retrieved" onEditSourceRevision={onEditSourceRevision} onUsePinnedSource={onUsePinnedSource} />)

    expect(await screen.findByText('Rule outcomes match; report hashes differ')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /reveal registry report sha-256/i })).toBeInTheDocument()
  })

  it.each([
    { failed_rules: ['AUTH-01'] },
    { severity: 'HIGH' as const },
    { implemented_rules: ['AUTH-01'] },
  ])('warns about differing rule results even when the overall status agrees: %j', async (difference) => {
    mocks.readLatestRegistryAudit.mockResolvedValue({
      ...authoritative,
      report: { ...report, ...difference, report_sha256: 'b'.repeat(64) },
    })
    render(<AttestationBoundary analysisLoading={false} report={report} sourceMode="retrieved" onEditSourceRevision={onEditSourceRevision} onUsePinnedSource={onUsePinnedSource} />)

    expect(await screen.findByRole('alert')).toHaveTextContent('Local and on-chain rule outcomes differ')
    expect(screen.getByRole('alert')).toHaveTextContent('Local:')
    expect(screen.getByRole('alert')).toHaveTextContent('On-chain:')
    expect(screen.queryByText('Rule outcomes match; report hashes differ')).not.toBeInTheDocument()
  })

  it('uses the typed supersession entrypoint when a prior audit ID is supplied', async () => {
    const user = userEvent.setup()
    window.ethereum = { request: vi.fn().mockResolvedValue([ADDRESS]) }
    mocks.readLatestRegistryAudit.mockResolvedValue(null)
    mocks.writeContract.mockResolvedValue(TX_HASH)
    mocks.waitForTransactionReceipt
      .mockResolvedValueOnce({ statusName: 'ACCEPTED', txExecutionResultName: 'FINISHED_WITH_RETURN' })
      .mockResolvedValueOnce({ statusName: 'FINALIZED', txExecutionResultName: 'FINISHED_WITH_RETURN' })
    mocks.readAuthoritativeAudit.mockResolvedValue(authoritative)

    render(<AttestationBoundary analysisLoading={false} report={report} sourceMode="retrieved" onEditSourceRevision={onEditSourceRevision} onUsePinnedSource={onUsePinnedSource} />)
    await user.click(screen.getByRole('button', { name: /connect wallet/i }))
    await user.type(await screen.findByLabelText(/supersedes audit id/i), '3')
    await user.click(screen.getByRole('button', { name: /request genlayer review/i }))

    expect(mocks.writeContract).toHaveBeenCalledWith({
      address: REGISTRY,
      functionName: 'request_superseding_audit',
      args: [SOURCE_URL, SOURCE_HASH, report.policy, 3n],
      value: 0n,
    })
  })

  it('distinguishes an absent audit from a failed registry lookup', async () => {
    mocks.readLatestRegistryAudit.mockResolvedValue(null)
    const { unmount } = render(<AttestationBoundary analysisLoading={false} report={report} sourceMode="retrieved" onEditSourceRevision={onEditSourceRevision} onUsePinnedSource={onUsePinnedSource} />)
    expect(await screen.findByText(/no existing audit for this exact source identity/i)).toBeInTheDocument()
    expect(screen.getByText('Start a new GenLayer review')).toBeInTheDocument()
    expect(screen.getByText(/connect rabby or metamask/i)).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()

    unmount()
    mocks.readLatestRegistryAudit.mockRejectedValue(new Error('RPC unavailable'))
    render(<AttestationBoundary analysisLoading={false} report={report} sourceMode="retrieved" onEditSourceRevision={onEditSourceRevision} onUsePinnedSource={onUsePinnedSource} />)
    expect(await screen.findByRole('alert')).toHaveTextContent(/registry lookup failed: rpc unavailable/i)
    expect(screen.getByRole('button', { name: /retry registry lookup/i })).toBeInTheDocument()
    expect(screen.queryByText('Start a new GenLayer review')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /request genlayer review/i })).not.toBeInTheDocument()
  })

  it('turns a submitted preview into an actionable pinned-source recovery step', async () => {
    const user = userEvent.setup()
    window.ethereum = { request: vi.fn().mockResolvedValue([ADDRESS]) }

    render(<AttestationBoundary analysisLoading={false} report={report} sourceMode="submitted" onEditSourceRevision={onEditSourceRevision} onUsePinnedSource={onUsePinnedSource} />)
    expect(screen.getByText(/this report used submitted editor bytes/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /request genlayer review/i })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /retrieve pinned source/i }))
    expect(onUsePinnedSource).toHaveBeenCalledOnce()
    expect(window.ethereum.request).not.toHaveBeenCalled()
    expect(mocks.writeContract).not.toHaveBeenCalled()
  })
})
