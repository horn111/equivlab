import type { TransactionHash } from 'genlayer-js/types'

export type AuditStatus = 'MEETS_BASELINE' | 'WARN' | 'FAIL' | 'UNVERIFIABLE'

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export interface Evidence {
  detail: string
  line: number
  symbol: string
}

export interface Finding {
  evidence: Evidence[]
  rule: string
  severity: Severity
  status: AuditStatus
  summary: string
}

export interface AuditReport {
  failed_rules: string[]
  findings: Finding[]
  implemented_rules: string[]
  policy: string
  report_sha256: string
  schema: string
  severity: Severity
  scope: string
  source: {
    canonical_sha256: string
    url: string
  }
  status: AuditStatus
  unverifiable_rules: string[]
  warning_rules: string[]
}

export interface AnalyzeResponse {
  report: AuditReport
  source_mode: 'retrieved' | 'submitted'
}

export interface SourceIdentity {
  repository: string
  commit: string
  path: string
  source: string
}

export type FixtureId = 'tip-jar' | 'schema-only' | 'hardened' | 'unverifiable'

export interface FixtureDefinition {
  id: FixtureId
  label: string
  path: string
  contract: string
  expected: AuditStatus
  note: string
  expectedRules: string[]
}

export interface HistoryRecord {
  id: string
  createdAt: string
  identity: SourceIdentity
  label: string
  provenance: 'reproduced' | 'snapshot'
  report: AuditReport
  sourceMode: AnalyzeResponse['source_mode']
}

export interface SharePayload {
  fixtureId: FixtureId
  identity: SourceIdentity
  report: AuditReport
  sourceMode: AnalyzeResponse['source_mode']
  version: 1
}

export interface OnChainAuditRecord {
  challenged: boolean
  challenged_by?: string
  challenge_reason_hash?: string
  created_at: string
  id: string
  policy: string
  requester: string
  source_hash: string
  source_url: string
  status: AuditStatus
  superseded_by: string | null
  supersedes_id: string | null
}

export interface OnChainReadback {
  audit: OnChainAuditRecord
  report: AuditReport
  transactionHash: TransactionHash | null
}
