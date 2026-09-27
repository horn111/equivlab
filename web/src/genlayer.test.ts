import { describe, expect, it, vi } from 'vitest'
import type { GenLayerTransaction, TransactionHash } from 'genlayer-js/types'
import {
  ensureWalletNetwork,
  isSuccessfulExecution,
  isUndeterminedReceipt,
  readAuthoritativeAudit,
  readLatestRegistryAudit,
  resolveGenLayerConfig,
  transactionExplorerUrl,
  walletErrorMessage,
} from './genlayer'

const ADDRESS = `0x${'1'.repeat(40)}` as const
const TX_HASH = `0x${'2'.repeat(64)}` as TransactionHash
const SOURCE_HASH = '3'.repeat(64)
const SOURCE_URL = `https://raw.githubusercontent.com/equivlab/demo/${'4'.repeat(40)}/contracts/example.py`
const OVERLAY = `0x${'8'.repeat(40)}` as const

describe('GenLayer deployment configuration', () => {
  it('keeps the on-chain boundary unavailable while deployment values are empty', () => {
    expect(resolveGenLayerConfig({} as ImportMetaEnv)).toEqual({ config: null, error: null })
  })

  it('rejects partial or malformed deployment values', () => {
    expect(resolveGenLayerConfig({ VITE_NETWORK_NAME: 'testnetBradbury' } as ImportMetaEnv).error).toMatch(/registry/i)
    expect(resolveGenLayerConfig({ VITE_NETWORK_NAME: 'unknown', VITE_REGISTRY_ADDRESS: ADDRESS } as ImportMetaEnv).error).toMatch(/one of/i)
  })

  it('resolves Bradbury RPC and explorer defaults without inventing deployment evidence', () => {
    const resolution = resolveGenLayerConfig({
      VITE_NETWORK_NAME: 'testnetBradbury',
      VITE_REGISTRY_ADDRESS: ADDRESS,
    } as ImportMetaEnv)
    expect(resolution.error).toBeNull()
    expect(resolution.config).toMatchObject({
      network: 'testnetBradbury',
      registryAddress: ADDRESS,
      explorerBaseUrl: 'https://explorer-bradbury.genlayer.com',
    })
    expect(transactionExplorerUrl(resolution.config!, TX_HASH)).toBe(`https://explorer-bradbury.genlayer.com/tx/${TX_HASH}`)
  })
})

describe('EIP-1193 wallet connection', () => {
  const config = resolveGenLayerConfig({
    VITE_NETWORK_NAME: 'testnetBradbury',
    VITE_REGISTRY_ADDRESS: ADDRESS,
  } as ImportMetaEnv).config!

  it('keeps a wallet that is already on Bradbury unchanged', async () => {
    const request = vi.fn().mockResolvedValue('0x107d')
    await ensureWalletNetwork(config, { request })
    expect(request).toHaveBeenCalledOnce()
    expect(request).toHaveBeenCalledWith({ method: 'eth_chainId' })
  })

  it('switches an existing Bradbury network without using MetaMask Snap methods', async () => {
    const request = vi.fn()
      .mockResolvedValueOnce('0x1')
      .mockResolvedValueOnce(null)
    await ensureWalletNetwork(config, { request })
    expect(request).toHaveBeenNthCalledWith(2, {
      method: 'wallet_switchEthereumChain',
      params: [{ chainId: '0x107d' }],
    })
    expect(request.mock.calls.flatMap((call) => call).join(' ')).not.toContain('wallet_getSnaps')
  })

  it('adds Bradbury when the wallet does not know the chain', async () => {
    const request = vi.fn()
      .mockResolvedValueOnce('0x1')
      .mockRejectedValueOnce({ code: 4902, message: 'Unknown chain' })
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce('0x107d')
    await ensureWalletNetwork(config, { request })
    expect(request).toHaveBeenNthCalledWith(3, {
      method: 'wallet_addEthereumChain',
      params: [expect.objectContaining({
        chainId: '0x107d',
        rpcUrls: ['https://rpc-bradbury.genlayer.com'],
      })],
    })
  })

  it('turns provider error objects into actionable copy', () => {
    expect(walletErrorMessage({ code: 4001 })).toBe('The wallet request was rejected.')
    expect(walletErrorMessage({ code: -32002 })).toMatch(/already pending/i)
    expect(walletErrorMessage({ message: 'Rabby transport failed' })).toBe('Rabby transport failed')
  })
})

describe('authoritative readback', () => {
  it('classifies execution and terminal undetermined receipts explicitly', () => {
    expect(isSuccessfulExecution({ txExecutionResultName: 'FINISHED_WITH_RETURN' } as GenLayerTransaction)).toBe(true)
    expect(isSuccessfulExecution({ txExecutionResultName: 'FINISHED_WITH_ERROR' } as GenLayerTransaction)).toBe(false)
    expect(isUndeterminedReceipt({ statusName: 'UNDETERMINED' } as GenLayerTransaction)).toBe(true)
    expect(isUndeterminedReceipt({ statusName: 'FINALIZED' } as GenLayerTransaction)).toBe(false)
  })

  it('accepts readback only when audit and report bind the submitted source identity', async () => {
    const readContract = vi.fn()
      .mockResolvedValueOnce('7')
      .mockResolvedValueOnce(JSON.stringify({
        challenged: false,
        created_at: '2026-08-25T00:00:00Z',
        id: '7',
        policy: 'gl-consensus-baseline-3',
        requester: ADDRESS,
        source_hash: SOURCE_HASH,
        source_url: SOURCE_URL,
        status: 'FAIL',
        superseded_by: null,
        supersedes_id: null,
      }))
      .mockResolvedValueOnce(JSON.stringify({
        failed_rules: ['AUTH-01'],
        findings: [],
        implemented_rules: ['AUTH-01'],
        policy: 'gl-consensus-baseline-3',
        report_sha256: '5'.repeat(64),
        schema: 'equivlab-report-v2',
        severity: 'CRITICAL',
        scope: 'Bounded on-chain observation.',
        source: { canonical_sha256: SOURCE_HASH, mode: 'retrieved', url: SOURCE_URL },
        status: 'FAIL',
        unverifiable_rules: [],
        warning_rules: [],
      }))
    const config = resolveGenLayerConfig({ VITE_NETWORK_NAME: 'testnetBradbury', VITE_REGISTRY_ADDRESS: ADDRESS } as ImportMetaEnv).config!
    const result = await readAuthoritativeAudit(
      { readContract } as never,
      config,
      SOURCE_HASH,
      SOURCE_URL,
      'gl-consensus-baseline-3',
      TX_HASH,
    )
    expect(result.audit.id).toBe('7')
    expect(result.report.status).toBe('FAIL')
    expect(readContract).toHaveBeenCalledTimes(3)
    expect(readContract).toHaveBeenNthCalledWith(1, {
      address: ADDRESS,
      functionName: 'get_latest',
      args: [SOURCE_URL, SOURCE_HASH, 'gl-consensus-baseline-3'],
    })
  })

  it('returns an explicit empty result when no exact source identity is registered', async () => {
    const readContract = vi.fn().mockResolvedValue('')
    const config = resolveGenLayerConfig({ VITE_NETWORK_NAME: 'testnetBradbury', VITE_REGISTRY_ADDRESS: ADDRESS } as ImportMetaEnv).config!
    await expect(readLatestRegistryAudit(
      { readContract } as never,
      config,
      SOURCE_HASH,
      SOURCE_URL,
      'gl-consensus-baseline-3',
    )).resolves.toBeNull()
    expect(readContract).toHaveBeenCalledWith({
      address: ADDRESS,
      functionName: 'get_latest',
      args: [SOURCE_URL, SOURCE_HASH, 'gl-consensus-baseline-3'],
    })
  })

  it('uses a source-matched PROMPT-01 correction without hiding the original registry report', async () => {
    const baseReport = {
      failed_rules: ['PROMPT-01'], findings: [], implemented_rules: ['AUTH-01', 'PROMPT-01'],
      policy: 'gl-consensus-baseline-3', report_sha256: 'a'.repeat(64), schema: 'equivlab-report-v2',
      severity: 'HIGH', scope: 'Base decision',
      source: { canonical_sha256: SOURCE_HASH, mode: 'retrieved', url: SOURCE_URL },
      status: 'FAIL', unverifiable_rules: [], warning_rules: [],
    }
    const corrected = {
      ...baseReport, failed_rules: [], findings: [], report_sha256: 'b'.repeat(64),
      severity: 'LOW', scope: 'Consensus-corrected decision', status: 'MEETS_BASELINE',
    }
    const patch = {
      audit_id: '7', base_registry: ADDRESS, base_report_sha256: baseReport.report_sha256,
      created_at: '2026-09-27T00:00:00Z', outcome: 'MEETS_BASELINE',
      report_sha256: corrected.report_sha256, source_hash: SOURCE_HASH, source_url: SOURCE_URL,
    }
    const audit = {
      challenged: false, created_at: '2026-09-27T00:00:00Z', id: '7',
      policy: baseReport.policy, requester: ADDRESS, source_hash: SOURCE_HASH,
      source_url: SOURCE_URL, status: 'FAIL', superseded_by: null, supersedes_id: null,
    }
    const readContract = vi.fn()
      .mockResolvedValueOnce('7')
      .mockResolvedValueOnce(JSON.stringify(audit))
      .mockResolvedValueOnce(JSON.stringify(baseReport))
      .mockResolvedValueOnce(JSON.stringify(patch))
      .mockResolvedValueOnce(JSON.stringify(corrected))
    const config = resolveGenLayerConfig({
      VITE_NETWORK_NAME: 'testnetBradbury', VITE_REGISTRY_ADDRESS: ADDRESS,
      VITE_PROMPT_OVERLAY_ADDRESS: OVERLAY,
    } as ImportMetaEnv).config!
    const readback = await readLatestRegistryAudit(
      { readContract } as never, config, SOURCE_HASH, SOURCE_URL, baseReport.policy,
    )
    expect(readback?.report.status).toBe('MEETS_BASELINE')
    expect(readback?.baseReport?.status).toBe('FAIL')
    expect(readback?.promptOverlay?.base_report_sha256).toBe(baseReport.report_sha256)
    expect(readContract).toHaveBeenNthCalledWith(4, {
      address: OVERLAY, functionName: 'get_patch', args: [7n], transactionHashVariant: 'latest-final',
    })
    expect(readContract).toHaveBeenNthCalledWith(5, {
      address: OVERLAY, functionName: 'get_report', args: [7n], transactionHashVariant: 'latest-final',
    })
  })

  it('rejects a correction that changes another rule or base report identity', async () => {
    const base = {
      failed_rules: ['PROMPT-01'], findings: [], implemented_rules: ['AUTH-01', 'PROMPT-01'],
      policy: 'gl-consensus-baseline-3', report_sha256: 'a'.repeat(64), schema: 'equivlab-report-v2',
      severity: 'HIGH', scope: 'Base decision',
      source: { canonical_sha256: SOURCE_HASH, mode: 'retrieved', url: SOURCE_URL },
      status: 'FAIL', unverifiable_rules: [], warning_rules: [],
    }
    const audit = {
      challenged: false, created_at: '2026-09-27T00:00:00Z', id: '7',
      policy: base.policy, requester: ADDRESS, source_hash: SOURCE_HASH,
      source_url: SOURCE_URL, status: 'FAIL', superseded_by: null, supersedes_id: null,
    }
    const patch = {
      audit_id: '7', base_registry: ADDRESS, base_report_sha256: base.report_sha256,
      created_at: '2026-09-27T00:00:00Z', outcome: 'MEETS_BASELINE', report_sha256: 'b'.repeat(64),
      source_hash: SOURCE_HASH, source_url: SOURCE_URL,
    }
    const changedOtherRule = { ...base, failed_rules: ['AUTH-01'], report_sha256: patch.report_sha256 }
    const readContract = vi.fn()
      .mockResolvedValueOnce('7')
      .mockResolvedValueOnce(JSON.stringify(audit))
      .mockResolvedValueOnce(JSON.stringify(base))
      .mockResolvedValueOnce(JSON.stringify(patch))
      .mockResolvedValueOnce(JSON.stringify(changedOtherRule))
    const config = resolveGenLayerConfig({
      VITE_NETWORK_NAME: 'testnetBradbury', VITE_REGISTRY_ADDRESS: ADDRESS,
      VITE_PROMPT_OVERLAY_ADDRESS: OVERLAY,
    } as ImportMetaEnv).config!
    await expect(readLatestRegistryAudit(
      { readContract } as never, config, SOURCE_HASH, SOURCE_URL, base.policy,
    )).rejects.toThrow(/PROMPT-01 correction does not match/i)
  })

  it('rejects a correction whose PROMPT-01 rule outcome contradicts the patch', async () => {
    const base = {
      failed_rules: ['PROMPT-01'], findings: [], implemented_rules: ['AUTH-01', 'PROMPT-01'],
      policy: 'gl-consensus-baseline-3', report_sha256: 'a'.repeat(64), schema: 'equivlab-report-v2',
      severity: 'HIGH', scope: 'Base decision',
      source: { canonical_sha256: SOURCE_HASH, mode: 'retrieved', url: SOURCE_URL },
      status: 'FAIL', unverifiable_rules: [], warning_rules: [],
    }
    const audit = {
      challenged: false, created_at: '2026-09-27T00:00:00Z', id: '7',
      policy: base.policy, requester: ADDRESS, source_hash: SOURCE_HASH,
      source_url: SOURCE_URL, status: 'FAIL', superseded_by: null, supersedes_id: null,
    }
    const corrected = { ...base, report_sha256: 'b'.repeat(64) }
    const patch = {
      audit_id: '7', base_registry: ADDRESS, base_report_sha256: base.report_sha256,
      created_at: '2026-09-27T00:00:00Z', outcome: 'MEETS_BASELINE',
      report_sha256: corrected.report_sha256, source_hash: SOURCE_HASH, source_url: SOURCE_URL,
    }
    const readContract = vi.fn()
      .mockResolvedValueOnce('7')
      .mockResolvedValueOnce(JSON.stringify(audit))
      .mockResolvedValueOnce(JSON.stringify(base))
      .mockResolvedValueOnce(JSON.stringify(patch))
      .mockResolvedValueOnce(JSON.stringify(corrected))
    const config = resolveGenLayerConfig({
      VITE_NETWORK_NAME: 'testnetBradbury', VITE_REGISTRY_ADDRESS: ADDRESS,
      VITE_PROMPT_OVERLAY_ADDRESS: OVERLAY,
    } as ImportMetaEnv).config!
    await expect(readLatestRegistryAudit(
      { readContract } as never, config, SOURCE_HASH, SOURCE_URL, base.policy,
    )).rejects.toThrow(/PROMPT-01 correction does not match/i)
  })
})
