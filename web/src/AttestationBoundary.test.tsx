import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { TransactionHash } from 'genlayer-js/types'
import AttestationBoundary from './AttestationBoundary'
import type { AuditReport, OnChainReadback } from './types'

const ADDRESS = `0x${'1'.repeat(40)}` as const
const REGISTRY = `0x${'2'.repeat(40)}` as const
const TX_HASH = `0x${'3'.repeat(64)}` as TransactionHash
const SOURCE_HASH = '4'.repeat(64)
const SOURCE_URL = `https://raw.githubusercontent.com/equivlab/demo/${'5'.repeat(40)}/fixtures/backdoored_tip_jar/contract.py`

const mocks = vi.hoisted(() => ({
  connect: vi.fn(),
  writeContract: vi.fn(),
  waitForTransactionReceipt: vi.fn(),
  readAuthoritativeAudit: vi.fn(),
}))

vi.mock('./genlayer', () => ({
  createGenLayerReadClient: () => ({ waitForTransactionReceipt: mocks.waitForTransactionReceipt }),
  createGenLayerWriteClient: () => ({ connect: mocks.connect, writeContract: mocks.writeContract }),
  isSuccessfulExecution: (receipt: { txExecutionResultName?: string }) => receipt.txExecutionResultName === 'FINISHED_WITH_RETURN',
  isUndeterminedReceipt: (receipt: { statusName?: string }) => receipt.statusName === 'UNDETERMINED',
  readAuthoritativeAudit: mocks.readAuthoritativeAudit,
  resolveGenLayerConfig: () => ({
    config: {
      explorerBaseUrl: 'https://explorer-bradbury.genlayer.com',
      network: 'testnetBradbury',
      registryAddress: REGISTRY,
    },
    error: null,
  }),
  transactionExplorerUrl: (_config: unknown, hash: string) => `https://explorer-bradbury.genlayer.com/tx/${hash}`,
}))

const report: AuditReport = {
  failed_rules: ['AUTH-01', 'VALUE-01'],
  findings: [],
  implemented_rules: ['AUTH-01', 'VALUE-01'],
  policy: 'gl-consensus-baseline-1',
  report_sha256: '6'.repeat(64),
  schema: 'equivlab-report-v1',
  severity: 'CRITICAL',
  scope: 'Test report.',
  source: { canonical_sha256: SOURCE_HASH, url: SOURCE_URL },
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
  delete window.ethereum
})

describe('attestation lifecycle', () => {
  it('claims authority only after a successful finalized receipt and source-matched readback', async () => {
    const user = userEvent.setup()
    window.ethereum = { request: vi.fn().mockResolvedValue([ADDRESS]) }
    mocks.writeContract.mockResolvedValue(TX_HASH)
    mocks.waitForTransactionReceipt
      .mockResolvedValueOnce({ statusName: 'ACCEPTED', txExecutionResultName: 'FINISHED_WITH_RETURN' })
      .mockResolvedValueOnce({ statusName: 'FINALIZED', txExecutionResultName: 'FINISHED_WITH_RETURN' })
    mocks.readAuthoritativeAudit.mockResolvedValue(authoritative)

    render(<AttestationBoundary report={report} sourceMode="retrieved" />)
    await user.click(screen.getByRole('button', { name: /connect wallet/i }))
    await user.click(await screen.findByRole('button', { name: /request attestation/i }))

    expect(await screen.findByRole('region', { name: /authoritative registry readback/i })).toBeInTheDocument()
    expect(screen.getByText('7')).toBeInTheDocument()
    expect(mocks.writeContract).toHaveBeenCalledWith({
      address: REGISTRY,
      functionName: 'request_audit',
      args: [SOURCE_URL, SOURCE_HASH, report.policy, ''],
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
})
