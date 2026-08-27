import { localnet, studionet, testnetAsimov, testnetBradbury } from 'genlayer-js/chains'
import type { GenLayerClient, GenLayerTransaction, TransactionHash } from 'genlayer-js/types'
import type { AuditReport, OnChainAuditRecord, OnChainReadback } from './types'

export const SUPPORTED_NETWORKS = ['localnet', 'studionet', 'testnetAsimov', 'testnetBradbury'] as const
export type SupportedNetwork = (typeof SUPPORTED_NETWORKS)[number]
export type RegistryAddress = `0x${string}`
type CreateClient = typeof import('genlayer-js')['createClient']
export type WalletProvider = NonNullable<NonNullable<Parameters<CreateClient>[0]>['provider']>

const NETWORKS = {
  localnet,
  studionet,
  testnetAsimov,
  testnetBradbury,
} as const

export interface GenLayerConfig {
  explorerBaseUrl: string
  network: SupportedNetwork
  registryAddress: RegistryAddress
  rpcUrl?: string
}

export interface ConfigResolution {
  config: GenLayerConfig | null
  error: string | null
}

let createClientPromise: Promise<CreateClient> | null = null

function loadCreateClient(): Promise<CreateClient> {
  createClientPromise ??= import('genlayer-js').then((module) => module.createClient)
  return createClientPromise
}

function cleanOptionalUrl(value: string | undefined): string | undefined {
  const trimmed = value?.trim()
  if (!trimmed) return undefined
  const parsed = new URL(trimmed)
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('RPC and explorer URLs must use HTTP or HTTPS.')
  return trimmed.replace(/\/$/, '')
}

export function resolveGenLayerConfig(env: ImportMetaEnv): ConfigResolution {
  const networkValue = env.VITE_NETWORK_NAME?.trim()
  const registryValue = env.VITE_REGISTRY_ADDRESS?.trim()
  if (!networkValue && !registryValue) return { config: null, error: null }
  if (!networkValue || !SUPPORTED_NETWORKS.includes(networkValue as SupportedNetwork)) {
    return { config: null, error: `VITE_NETWORK_NAME must be one of: ${SUPPORTED_NETWORKS.join(', ')}.` }
  }
  if (!registryValue || !/^0x[0-9a-fA-F]{40}$/.test(registryValue)) {
    return { config: null, error: 'VITE_REGISTRY_ADDRESS must be a 20-byte 0x-prefixed address.' }
  }

  try {
    const rpcUrl = cleanOptionalUrl(env.VITE_GENLAYER_RPC_URL)
    const configuredExplorer = cleanOptionalUrl(env.VITE_EXPLORER_BASE_URL)
    const chainExplorer = NETWORKS[networkValue as SupportedNetwork].blockExplorers?.default.url.replace(/\/$/, '')
    return {
      config: {
        explorerBaseUrl: configuredExplorer ?? chainExplorer ?? '',
        network: networkValue as SupportedNetwork,
        registryAddress: registryValue as RegistryAddress,
        ...(rpcUrl ? { rpcUrl } : {}),
      },
      error: null,
    }
  } catch (error) {
    return { config: null, error: error instanceof Error ? error.message : 'Invalid GenLayer deployment configuration.' }
  }
}

export async function createGenLayerReadClient(config: GenLayerConfig) {
  const createClient = await loadCreateClient()
  return createClient({ chain: NETWORKS[config.network], ...(config.rpcUrl ? { endpoint: config.rpcUrl } : {}) })
}

export async function createGenLayerWriteClient(config: GenLayerConfig, account: RegistryAddress, provider: WalletProvider) {
  const createClient = await loadCreateClient()
  return createClient({
    chain: NETWORKS[config.network],
    account,
    provider,
    ...(config.rpcUrl ? { endpoint: config.rpcUrl } : {}),
  })
}

function parseJsonObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'string') throw new Error(`${label} readback was not a JSON string.`)
  const parsed: unknown = JSON.parse(value)
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(`${label} readback was not an object.`)
  return parsed as Record<string, unknown>
}

function parseAudit(value: unknown): OnChainAuditRecord {
  const audit = parseJsonObject(value, 'Audit')
  if (
    typeof audit.id !== 'string'
    || typeof audit.policy !== 'string'
    || typeof audit.source_hash !== 'string'
    || typeof audit.source_url !== 'string'
    || typeof audit.status !== 'string'
    || typeof audit.requester !== 'string'
    || typeof audit.created_at !== 'string'
    || typeof audit.challenged !== 'boolean'
  ) {
    throw new Error('Audit readback omitted required identity fields.')
  }
  return audit as unknown as OnChainAuditRecord
}

function parseReport(value: unknown): AuditReport {
  const report = parseJsonObject(value, 'Report')
  if (
    typeof report.policy !== 'string'
    || typeof report.status !== 'string'
    || typeof report.report_sha256 !== 'string'
    || !report.source
    || typeof report.source !== 'object'
  ) {
    throw new Error('Report readback omitted required policy fields.')
  }
  return report as unknown as AuditReport
}

export async function readAuthoritativeAudit(
  client: GenLayerClient<(typeof NETWORKS)[SupportedNetwork]>,
  config: GenLayerConfig,
  sourceHash: string,
  sourceUrl: string,
  policy: string,
  txHash: TransactionHash,
): Promise<OnChainReadback> {
  const readback = await readLatestRegistryAudit(client, config, sourceHash, sourceUrl, policy, txHash)
  if (!readback) throw new Error('The finalized transaction did not create a source-matched registry audit.')
  return readback
}

export async function readLatestRegistryAudit(
  client: GenLayerClient<(typeof NETWORKS)[SupportedNetwork]>,
  config: GenLayerConfig,
  sourceHash: string,
  sourceUrl: string,
  policy: string,
  txHash: TransactionHash | null = null,
): Promise<OnChainReadback | null> {
  const latest = await client.readContract({
    address: config.registryAddress,
    functionName: 'get_latest',
    args: [sourceUrl, sourceHash, policy],
  })
  if (latest === '') return null
  if (typeof latest !== 'string' || !/^(0|[1-9][0-9]*)$/.test(latest)) {
    throw new Error('The registry did not return a canonical audit ID for this source revision.')
  }

  const auditId = BigInt(latest)
  const [auditValue, reportValue] = await Promise.all([
    client.readContract({ address: config.registryAddress, functionName: 'get_audit', args: [auditId] }),
    client.readContract({ address: config.registryAddress, functionName: 'get_report', args: [auditId] }),
  ])
  const audit = parseAudit(auditValue)
  const report = parseReport(reportValue)
  if (
    audit.id !== latest
    || audit.source_hash !== sourceHash
    || audit.source_url !== sourceUrl
    || audit.policy !== policy
    || report.source.canonical_sha256 !== sourceHash
    || report.source.url !== sourceUrl
    || report.policy !== policy
  ) {
    throw new Error('Authoritative readback does not match the requested source identity and policy.')
  }
  return { audit, report, transactionHash: txHash }
}

export function isSuccessfulExecution(receipt: GenLayerTransaction): boolean {
  return receipt.txExecutionResultName === 'FINISHED_WITH_RETURN'
}

export function isUndeterminedReceipt(receipt: GenLayerTransaction): boolean {
  return ['UNDETERMINED', 'CANCELED', 'VALIDATORS_TIMEOUT', 'LEADER_TIMEOUT'].includes(receipt.statusName ?? '')
}

export function transactionExplorerUrl(config: GenLayerConfig, txHash: string): string | null {
  return config.explorerBaseUrl ? `${config.explorerBaseUrl}/tx/${txHash}` : null
}
