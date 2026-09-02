import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { KeyboardEvent } from 'react'
import { ArrowClockwiseIcon } from '@phosphor-icons/react/ArrowClockwise'
import { ArrowRightIcon } from '@phosphor-icons/react/ArrowRight'
import { CheckIcon } from '@phosphor-icons/react/Check'
import { CodeIcon } from '@phosphor-icons/react/Code'
import { GitCommitIcon } from '@phosphor-icons/react/GitCommit'
import { GithubLogoIcon } from '@phosphor-icons/react/GithubLogo'
import { LinkIcon } from '@phosphor-icons/react/Link'
import { PulseIcon } from '@phosphor-icons/react/Pulse'
import { ShieldWarningIcon } from '@phosphor-icons/react/ShieldWarning'
import { SpinnerGapIcon } from '@phosphor-icons/react/SpinnerGap'
import { WarningCircleIcon } from '@phosphor-icons/react/WarningCircle'
import { XIcon } from '@phosphor-icons/react/X'
import backdooredTipJar from '../../fixtures/backdoored_tip_jar/contract.py?raw'
import hardenedFactChecker from '../../fixtures/hardened_fact_checker/contract.py?raw'
import schemaOnlyFactChecker from '../../fixtures/schema_only_fact_checker/contract.py?raw'
import type {
  AnalyzeResponse,
  AuditReport,
  AuditStatus,
  Finding,
  FixtureDefinition,
  FixtureId,
  HistoryRecord,
  SharePayload,
  SourceIdentity,
} from './types'
import AttestationBoundary from './AttestationBoundary'
import ExactValue from './ExactValue'

const POLICY_ID = 'gl-consensus-baseline-2'
const DEMO_REPOSITORY = import.meta.env.VITE_DEMO_REPOSITORY?.trim() || 'horn111/equivlab'
const PINNED_COMMIT = import.meta.env.VITE_DEMO_COMMIT?.trim() || 'aef703943cef6a6d9c3f65545072711d78d44417'
const RULES = [
  ['SRC-01', 'Pinned source identity', 'CRITICAL'],
  ['CONS-01', 'GenLayer consensus eligibility', 'CRITICAL'],
  ['RESULT-01', 'Fail-closed result handling', 'HIGH'],
  ['BOUND-01', 'Bounded model-derived state', 'HIGH'],
  ['AUTH-01', 'Caller-derived transfer authority', 'CRITICAL'],
  ['VALUE-01', 'Deterministic transfer fields', 'CRITICAL'],
  ['EVID-01', 'Validator evidence re-observation', 'HIGH'],
  ['PROMPT-01', 'Untrusted prompt framing', 'HIGH'],
  ['URL-01', 'Web source constraints', 'MEDIUM'],
  ['STATE-01', 'Post-consensus state writes', 'HIGH'],
  ['REPLAY-01', 'Settlement replay guard', 'HIGH'],
  ['TIME-01', 'Authoritative timestamp source', 'MEDIUM'],
] as const
const RULE_IDS = RULES.map(([rule]) => rule)
const RULE_ID_SET = new Set<string>(RULE_IDS)
const IMPLEMENTED_RULE_IDS = [...RULE_IDS].sort()
const RULE_SEVERITY = new Map<string, string>(RULES.map(([rule, , severity]) => [rule, severity]))
const SEVERITY_ORDER = new Map([['LOW', 0], ['MEDIUM', 1], ['HIGH', 2], ['CRITICAL', 3]])

const FIXTURES: FixtureDefinition[] = [
  {
    id: 'tip-jar',
    label: 'Permissionless tip jar',
    path: 'fixtures/backdoored_tip_jar/contract.py',
    contract: backdooredTipJar,
    expected: 'FAIL',
    expectedRules: ['AUTH-01', 'VALUE-01'],
    note: 'Structurally valid contract with an unguarded, caller-selected withdrawal recipient.',
  },
  {
    id: 'schema-only',
    label: 'Schema-only validator',
    path: 'fixtures/schema_only_fact_checker/contract.py',
    contract: schemaOnlyFactChecker,
    expected: 'FAIL',
    expectedRules: ['CONS-01', 'EVID-01'],
    note: 'Validator checks leader output shape but does not independently re-evaluate evidence.',
  },
  {
    id: 'hardened',
    label: 'Hardened fact checker',
    path: 'fixtures/hardened_fact_checker/contract.py',
    contract: hardenedFactChecker,
    expected: 'MEETS_BASELINE',
    expectedRules: [],
    note: 'Independent evaluation, bounded state, explicit result handling, and framed evidence.',
  },
  {
    id: 'unverifiable',
    label: 'Hash mismatch',
    path: 'fixtures/backdoored_tip_jar/contract.py',
    contract: backdooredTipJar,
    expected: 'UNVERIFIABLE',
    expectedRules: ['SRC-01'],
    note: 'Supplied source bytes cannot be bound to the claimed digest.',
  },
]

const STATUS_COPY: Record<AuditStatus, string> = {
  MEETS_BASELINE: 'Meets implemented baseline',
  WARN: 'Bounded warning',
  FAIL: 'Policy violation found',
  UNVERIFIABLE: 'Source or facts unverified',
}

const RULE_NEXT_CHANGE: Partial<Record<string, string>> = {
  'SRC-01': 'Fetch the commit-pinned source again and bind the report to its canonical digest.',
  'CONS-01': 'Use a gl.Contract public write entrypoint with a reachable run_nondet_unsafe path, then re-evaluate the claim independently in its validator.',
  'AUTH-01': 'Require caller-derived authorization before any public value-transfer path can execute.',
  'VALUE-01': 'Derive recipient and amount from deterministic, authorized state rather than caller input.',
  'EVID-01': 'Re-observe material evidence inside the validator before accepting the result.',
}

const STORAGE_KEY = 'equivlab:history:v2'

export function canonicalizeSource(source: string): string {
  const withoutBom = source.charCodeAt(0) === 0xfeff ? source.slice(1) : source
  const normalized = withoutBom.replace(/\r\n?/g, '\n')
  return normalized.endsWith('\n') ? normalized : `${normalized}\n`
}

export async function sourceSha256(source: string): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalizeSource(source))
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function sortJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortJson)
  if (!value || typeof value !== 'object') return value
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => [key, sortJson(entry)]),
  )
}

async function textSha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

export async function reportSha256(report: AuditReport): Promise<string> {
  const { report_sha256: _claimed, ...unsigned } = report
  return textSha256(JSON.stringify(sortJson(unsigned)))
}

export function pinnedSourceUrl(identity: Pick<SourceIdentity, 'repository' | 'commit' | 'path'>): string {
  const repository = identity.repository.trim().replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '')
  const path = identity.path.trim().replace(/^\/+/, '')
  return `https://raw.githubusercontent.com/${repository}/${identity.commit.trim()}/${path}`
}

function fixtureById(id: FixtureId): FixtureDefinition {
  return FIXTURES.find((fixture) => fixture.id === id) ?? FIXTURES[0]
}

function fixtureIdentity(fixture: FixtureDefinition): SourceIdentity {
  return {
    repository: DEMO_REPOSITORY,
    commit: PINNED_COMMIT,
    path: fixture.path,
    source: fixture.contract,
  }
}

async function analyzeRevision(
  sourceUrl: string,
  expectedSha256: string,
  source: string | undefined,
  signal?: AbortSignal,
): Promise<AnalyzeResponse> {
  const response = await fetch('/api/analyze', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      source_url: sourceUrl,
      expected_sha256: expectedSha256,
      ...(source === undefined ? {} : { source }),
    }),
    signal,
  })
  const payload: unknown = await response.json().catch(() => null)
  if (!response.ok || !payload || typeof payload !== 'object' || !('report' in payload)) {
    const payloadRecord = payload && typeof payload === 'object' ? payload as Record<string, unknown> : null
    const baseMessage = payloadRecord && typeof payloadRecord.error === 'string'
      ? payloadRecord.error
      : response.status === 429
        ? 'The analyzer is handling too many requests. Wait briefly, then retry this revision.'
        : 'The analyzer returned an invalid response.'
    const requestId = payloadRecord && typeof payloadRecord.request_id === 'string' ? payloadRecord.request_id : null
    throw new Error(requestId ? `${baseMessage} Support reference: ${requestId}.` : baseMessage)
  }
  return payload as AnalyzeResponse
}

function loadHistory(): HistoryRecord[] {
  try {
    const value = localStorage.getItem(STORAGE_KEY)
    if (!value) return []
    const parsed: unknown = JSON.parse(value)
    if (!Array.isArray(parsed)) return []
    return parsed
      .map(parseStoredHistoryRecord)
      .filter((record): record is HistoryRecord => record !== null)
      .slice(0, 12)
  } catch {
    return []
  }
}

function shortHash(value: string, size = 9): string {
  if (!value) return 'not set'
  return `${value.slice(0, size)}…${value.slice(-5)}`
}

function encodeSharePayload(payload: SharePayload): string {
  const bytes = new TextEncoder().encode(JSON.stringify(payload))
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}

const AUDIT_STATUSES = new Set<AuditStatus>(['MEETS_BASELINE', 'WARN', 'FAIL', 'UNVERIFIABLE'])
const SEVERITIES = new Set(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
const SOURCE_MODES = new Set<AnalyzeResponse['source_mode']>(['retrieved', 'submitted'])
const HASH_256 = /^[a-f0-9]{64}$/
const COMMIT_SHA = /^[a-f0-9]{40}$/

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string')
}

function hasExactRules(value: string[], expected: readonly string[]): boolean {
  return value.length === expected.length
    && value.every((rule, index) => rule === expected[index])
}

function isUniqueKnownRuleArray(value: unknown): value is string[] {
  return isStringArray(value)
    && new Set(value).size === value.length
    && value.every((rule) => RULE_ID_SET.has(rule))
}

function isSourceIdentity(value: unknown): value is SourceIdentity {
  if (!value || typeof value !== 'object') return false
  const identity = value as Record<string, unknown>
  return typeof identity.repository === 'string'
    && identity.repository.length > 0
    && typeof identity.commit === 'string'
    && COMMIT_SHA.test(identity.commit)
    && typeof identity.path === 'string'
    && identity.path.length > 0
    && typeof identity.source === 'string'
}

function isFinding(value: unknown): value is Finding {
  if (!value || typeof value !== 'object') return false
  const finding = value as Record<string, unknown>
  return typeof finding.rule === 'string'
    && RULES.some(([rule]) => rule === finding.rule)
    && typeof finding.status === 'string'
    && AUDIT_STATUSES.has(finding.status as AuditStatus)
    && finding.status !== 'MEETS_BASELINE'
    && typeof finding.severity === 'string'
    && SEVERITIES.has(finding.severity)
    && finding.severity === RULE_SEVERITY.get(finding.rule as string)
    && typeof finding.summary === 'string'
    && Array.isArray(finding.evidence)
    && finding.evidence.every((entry) => {
      if (!entry || typeof entry !== 'object') return false
      const evidence = entry as Record<string, unknown>
      return typeof evidence.detail === 'string'
        && Number.isInteger(evidence.line)
        && typeof evidence.symbol === 'string'
    })
}

function expectedReportStatus(failed: string[], warnings: string[], unverifiable: string[]): AuditStatus {
  if (failed.length) return 'FAIL'
  if (unverifiable.length) return 'UNVERIFIABLE'
  if (warnings.length) return 'WARN'
  return 'MEETS_BASELINE'
}

function expectedReportSeverity(findings: Finding[]): string {
  return findings.reduce(
    (highest, finding) => (SEVERITY_ORDER.get(finding.severity)! > SEVERITY_ORDER.get(highest)! ? finding.severity : highest),
    'LOW',
  )
}

function isAuditReport(value: unknown): value is AuditReport {
  if (!value || typeof value !== 'object') return false
  const report = value as Record<string, unknown>
  const source = report.source as Record<string, unknown> | undefined
  if (!(report.schema === 'equivlab-report-v1'
    && report.policy === POLICY_ID
    && typeof report.status === 'string'
    && AUDIT_STATUSES.has(report.status as AuditStatus)
    && typeof report.severity === 'string'
    && SEVERITIES.has(report.severity)
    && typeof report.scope === 'string'
    && typeof report.report_sha256 === 'string'
    && HASH_256.test(report.report_sha256)
    && isUniqueKnownRuleArray(report.failed_rules)
    && isStringArray(report.implemented_rules)
    && isUniqueKnownRuleArray(report.unverifiable_rules)
    && isUniqueKnownRuleArray(report.warning_rules)
    && Array.isArray(report.findings)
    && report.findings.every(isFinding)
    && !!source
    && typeof source.url === 'string'
    && typeof source.canonical_sha256 === 'string'
    && HASH_256.test(source.canonical_sha256))) return false

  const implemented = report.implemented_rules as string[]
  const failed = report.failed_rules as string[]
  const warnings = report.warning_rules as string[]
  const unverifiable = report.unverifiable_rules as string[]
  const findings = report.findings as Finding[]
  const partitions = [...failed, ...warnings, ...unverifiable]
  if (!hasExactRules(implemented, IMPLEMENTED_RULE_IDS) || new Set(partitions).size !== partitions.length) return false

  const findingRules = findings.map((finding) => finding.rule)
  if (new Set(findingRules).size !== findingRules.length || !hasExactRules([...findingRules].sort(), [...partitions].sort())) return false
  if (findings.some((finding) => (
    finding.status === 'FAIL' ? !failed.includes(finding.rule)
      : finding.status === 'WARN' ? !warnings.includes(finding.rule)
        : !unverifiable.includes(finding.rule)
  ))) return false

  return report.status === expectedReportStatus(failed, warnings, unverifiable)
    && report.severity === expectedReportSeverity(findings)
}

function isCoherentResult(identity: SourceIdentity, report: AuditReport): boolean {
  return report.source.url === pinnedSourceUrl(identity)
}

async function isReproducedResponse(
  identity: SourceIdentity,
  sourceDigest: string,
  response: AnalyzeResponse,
): Promise<boolean> {
  return SOURCE_MODES.has(response.source_mode)
    && isAuditReport(response.report)
    && isCoherentResult(identity, response.report)
    && response.report.source.canonical_sha256 === sourceDigest
    && response.report.report_sha256 === await reportSha256(response.report)
}

function parseStoredHistoryRecord(value: unknown): HistoryRecord | null {
  if (!value || typeof value !== 'object') return null
  const record = value as Record<string, unknown>
  const valid = typeof record.id === 'string'
    && typeof record.createdAt === 'string'
    && !Number.isNaN(Date.parse(record.createdAt))
    && typeof record.label === 'string'
    && isSourceIdentity(record.identity)
    && isAuditReport(record.report)
    && isCoherentResult(record.identity, record.report)
    && typeof record.sourceMode === 'string'
    && SOURCE_MODES.has(record.sourceMode as AnalyzeResponse['source_mode'])
  if (!valid) return null
  return {
    id: record.id as string,
    createdAt: record.createdAt as string,
    identity: record.identity as SourceIdentity,
    label: record.label as string,
    provenance: 'snapshot',
    report: record.report as AuditReport,
    sourceMode: record.sourceMode as AnalyzeResponse['source_mode'],
  }
}

function isSharePayload(value: unknown): value is SharePayload {
  if (!value || typeof value !== 'object') return false
  const payload = value as Record<string, unknown>
  return payload.version === 1
    && typeof payload.fixtureId === 'string'
    && FIXTURES.some((fixture) => fixture.id === payload.fixtureId)
    && isSourceIdentity(payload.identity)
    && isAuditReport(payload.report)
    && isCoherentResult(payload.identity, payload.report)
    && typeof payload.sourceMode === 'string'
    && SOURCE_MODES.has(payload.sourceMode as AnalyzeResponse['source_mode'])
}

function readSharePayload(): SharePayload | null {
  try {
    const encoded = new URLSearchParams(window.location.hash.slice(1)).get('r')
    if (!encoded) return null
    const padded = encoded.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - encoded.length % 4) % 4)
    const binary = atob(padded)
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0))
    const payload: unknown = JSON.parse(new TextDecoder().decode(bytes))
    return isSharePayload(payload) ? payload : null
  } catch {
    return null
  }
}

function StatusMark({ status, compact = false }: { status: AuditStatus; compact?: boolean }) {
  const Icon = status === 'MEETS_BASELINE' ? CheckIcon : status === 'FAIL' ? XIcon : WarningCircleIcon
  return (
    <span className={`status-mark status-${status.toLowerCase()} ${compact ? 'status-compact' : ''}`}>
      <Icon aria-hidden="true" weight="bold" />
      {compact ? status : STATUS_COPY[status]}
    </span>
  )
}

type RuleDisplayStatus = AuditStatus | 'UNKNOWN'

function ruleStatus(report: AuditReport, rule: string): RuleDisplayStatus {
  const finding = report.findings.find((item) => item.rule === rule)
  if (finding) return finding.status
  return report.implemented_rules.includes(rule) ? 'MEETS_BASELINE' : 'UNKNOWN'
}

function moveRuleFocus(event: KeyboardEvent<HTMLButtonElement>, index: number, total: number) {
  const direction = event.key === 'ArrowDown' || event.key === 'ArrowRight'
    ? 1
    : event.key === 'ArrowUp' || event.key === 'ArrowLeft'
      ? -1
      : 0
  const targetIndex = event.key === 'Home'
    ? 0
    : event.key === 'End'
      ? total - 1
      : direction
        ? (index + direction + total) % total
        : null
  if (targetIndex === null) return
  event.preventDefault()
  const buttons = event.currentTarget.closest('ol, .spectrum-lines')?.querySelectorAll<HTMLButtonElement>('button')
  buttons?.[targetIndex]?.focus()
  buttons?.[targetIndex]?.click()
}

function PolicyRail({ activeRule, onSelect }: { activeRule: string | null; onSelect: (rule: string) => void }) {
  return (
    <aside className="policy-rail" aria-label="Policy rule rail">
      <div className="brand-lockup">
        <svg className="brand-mark" viewBox="0 0 44 44" aria-hidden="true">
          <path className="brand-frame" d="M4.5 4.5h13M4.5 4.5v35h13M39.5 4.5h-13M39.5 4.5v35h-13" />
          <path className="brand-rail brand-rail-top" d="M11 14h16l6 4" />
          <path className="brand-rail brand-rail-mid" d="M11 22h22" />
          <path className="brand-rail brand-rail-bottom" d="M11 30h16l6-4" />
          <circle className="brand-node" cx="33" cy="22" r="2.5" />
        </svg>
        <span className="brand-copy">
          <strong>EquivLab</strong>
          <small>Consensus diagnostics</small>
        </span>
        <code className="mobile-active-rule">{activeRule ?? 'NO RULE'}</code>
      </div>
      <div className="rail-heading">
        <span>POLICY</span>
        <strong>{POLICY_ID}</strong>
      </div>
      <ol className="rail-rules">
        {RULES.map(([rule], index) => (
          <li key={rule}>
            <button
              className={activeRule === rule ? 'active' : ''}
              onClick={() => onSelect(rule)}
              onKeyDown={(event) => moveRuleFocus(event, index, RULES.length)}
              aria-pressed={activeRule === rule}
              tabIndex={activeRule === rule ? 0 : -1}
              title={`Inspect ${rule}`}
            >
              <span className="rail-index">{String(index + 1).padStart(2, '0')}</span>
              <span className="rail-tick" />
              <span>{rule}</span>
            </button>
          </li>
        ))}
      </ol>
      <p className="rail-footnote">Deterministic core<br />12 implemented rules</p>
    </aside>
  )
}

function FixtureStrip({
  selected,
  onSelect,
}: {
  selected: FixtureId
  onSelect: (id: FixtureId) => void
}) {
  return (
    <>
      <label className="fixture-picker">
        <span>Reference fixture</span>
        <select value={selected} onChange={(event) => onSelect(event.target.value as FixtureId)}>
          {FIXTURES.map((fixture) => <option key={fixture.id} value={fixture.id}>{fixture.label}</option>)}
        </select>
      </label>
      <nav className="fixture-strip" aria-label="Reference fixture outcomes">
        {FIXTURES.map((fixture) => (
          <button
            key={fixture.id}
            onClick={() => onSelect(fixture.id)}
            className={selected === fixture.id ? 'selected' : ''}
            aria-pressed={selected === fixture.id}
          >
            <span className={`fixture-signal status-${fixture.expected.toLowerCase()}`} />
            <span>
              <strong>{fixture.label}</strong>
              <small>{fixture.expectedRules.length ? fixture.expectedRules.join(' + ') : fixture.expected}</small>
            </span>
          </button>
        ))}
      </nav>
    </>
  )
}

function RuleSpectrum({
  report,
  activeRule,
  onSelect,
  loading,
}: {
  report: AuditReport | null
  activeRule: string | null
  onSelect: (rule: string) => void
  loading: boolean
}) {
  const findingMap = useMemo(
    () => new Map(report?.findings.map((finding) => [finding.rule, finding]) ?? []),
    [report],
  )
  return (
    <section className="spectrum-panel" aria-labelledby="spectrum-title" aria-busy={loading}>
      <div className="panel-heading">
        <div>
          <h2 id="spectrum-title">Implemented rules</h2>
          <p>Select a rule to inspect its local evidence.</p>
        </div>
      </div>
      <div className="spectrum-scale" aria-hidden="true">
        <span>LOCAL PRECHECK</span><span>12 RULES</span><span>REPORT HASH</span>
      </div>
      <div className="spectrum-lines">
        {RULES.map(([rule, title, severity], index) => {
          const finding = findingMap.get(rule)
          const status: RuleDisplayStatus | 'IDLE' = report
            ? ruleStatus(report, rule)
            : 'IDLE'
          return (
            <button
              key={rule}
              className={`spectrum-line spectrum-${status.toLowerCase()} ${activeRule === rule ? 'active' : ''}`}
              onClick={() => onSelect(rule)}
              onKeyDown={(event) => moveRuleFocus(event, index, RULES.length)}
              disabled={!report}
              tabIndex={activeRule === rule ? 0 : -1}
            >
              <span className="line-number">{String(index + 1).padStart(2, '0')}</span>
              <span className="line-rule">{rule}</span>
              <span className="line-title">{title}</span>
              <span className="line-severity">{severity}</span>
              <span className="line-signal" aria-hidden="true"><i /></span>
              <span className="line-status">{status === 'IDLE' ? 'UNREAD' : status}</span>
            </button>
          )
        })}
      </div>
      {loading && (
        <div className="analyzing-bar" role="status">
          <SpinnerGapIcon aria-hidden="true" className="spin" />
          Building deterministic AST and call paths
        </div>
      )}
    </section>
  )
}

function RuleFocus({ report, activeRule }: { report: AuditReport | null; activeRule: string | null }) {
  const rule = RULES.find(([id]) => id === activeRule)
  if (!activeRule || !rule) return null
  const status: RuleDisplayStatus | 'UNREAD' = report ? ruleStatus(report, activeRule) : 'UNREAD'
  return (
    <div className="rule-focus" role="status" aria-live="polite" aria-label="Selected rule">
      <div className="rule-focus-id"><span>SELECTED RULE</span><code>{activeRule}</code></div>
      <div className="rule-focus-copy"><strong>{rule[1]}</strong></div>
      {status === 'UNREAD' || status === 'UNKNOWN'
        ? <span className={`rule-focus-${status.toLowerCase()}`}>{status}</span>
        : <StatusMark status={status} compact />}
    </div>
  )
}

function FindingReadout({ finding, activeRule, report }: { finding: Finding | null; activeRule: string | null; report: AuditReport | null }) {
  const rule = RULES.find(([id]) => id === activeRule)
  if (!activeRule || !rule) {
    return (
      <div className="finding-empty">
        <PulseIcon aria-hidden="true" />
        <p>Select a rule mark to inspect its evidence.</p>
      </div>
    )
  }
  if (!report) {
    return (
      <div className="finding-readout finding-unread">
        <div className="finding-rule"><span>{activeRule}</span><span>UNREAD</span></div>
        <h3>{rule[1]}</h3>
        <p>Run analysis before interpreting this rule.</p>
      </div>
    )
  }
  if (!finding) {
    const status = ruleStatus(report, activeRule)
    if (status === 'UNKNOWN') {
      return (
        <div className="finding-readout finding-unknown">
          <div className="finding-rule"><span>{activeRule}</span><span>UNKNOWN</span></div>
          <h3>{rule[1]}</h3>
          <p>This report did not establish an implemented result for the selected rule.</p>
        </div>
      )
    }
    return (
      <div className="finding-readout finding-pass">
        <div className="finding-rule"><span>{activeRule}</span><StatusMark status="MEETS_BASELINE" compact /></div>
        <h3>{rule[1]}</h3>
        <p>No non-passing evidence was emitted for this rule.</p>
      </div>
    )
  }
  return (
    <div className={`finding-readout finding-${finding.status.toLowerCase()}`}>
      <div className="finding-rule"><span>{finding.rule}</span><StatusMark status={finding.status} compact /></div>
      <h3>{finding.summary}</h3>
      {finding.evidence.length === 0 ? (
        <p>The analyzer could not establish facts required by this rule.</p>
      ) : (
        <ol className="evidence-list">
          {finding.evidence.map((evidence) => (
            <li key={`${evidence.line}-${evidence.symbol}-${evidence.detail}`}>
              <span>LINE {evidence.line}</span>
              <code>{evidence.symbol}</code>
              <p>{evidence.detail}</p>
            </li>
          ))}
        </ol>
      )}
      <div className="finding-guidance">
        <span>NEXT CHANGE</span>
        <p>{RULE_NEXT_CHANGE[finding.rule] ?? 'Review the cited evidence, change the contract, then reproduce the report.'}</p>
      </div>
    </div>
  )
}

function HistoryArchive({
  records,
  selected,
  onToggle,
  onRestore,
}: {
  records: HistoryRecord[]
  selected: string[]
  onToggle: (id: string) => void
  onRestore: (record: HistoryRecord) => void
}) {
  const compared = records.filter((record) => selected.includes(record.id)).slice(0, 2)
  return (
    <details className="history-archive">
      <summary className="archive-heading">
        <div><h2 id="history-title">Recent local reports</h2><p>Last 12 browser-local records. Reloaded records are snapshots until reproduced; none is an on-chain attestation.</p></div>
        <span>{records.length} / 12 STORED</span>
      </summary>
      <div aria-labelledby="history-title">
      {records.length === 0 ? (
        <div className="archive-empty"><CodeIcon /><p>Run a fixture or pinned revision to create the first local record.</p></div>
      ) : (
        <div className="archive-list">
          {records.map((record) => (
            <article key={record.id}>
              <button
                className="compare-check"
                onClick={() => onToggle(record.id)}
                aria-pressed={selected.includes(record.id)}
                disabled={record.provenance === 'snapshot'}
                title={record.provenance === 'snapshot' ? 'Reproduce this snapshot before comparison.' : undefined}
              >
                <span>{selected.includes(record.id) ? <CheckIcon weight="bold" /> : null}</span> Compare
              </button>
              <div><strong>{record.label}</strong><small>{new Date(record.createdAt).toLocaleString()}</small></div>
              {record.provenance === 'reproduced'
                ? <StatusMark status={record.report.status} compact />
                : <span className="snapshot-label">UNVERIFIED SNAPSHOT</span>}
              <div className="archive-identity">
                <code>COMMIT {shortHash(record.identity.commit, 7)}</code>
                <code>REPORT {shortHash(record.report.report_sha256, 9)}</code>
              </div>
              <button className="restore-record" onClick={() => onRestore(record)}>
                {record.provenance === 'snapshot' ? 'Reproduce report' : 'Open report'} <ArrowRightIcon />
              </button>
            </article>
          ))}
        </div>
      )}
      {compared.length === 2 && <RevisionComparison left={compared[0]} right={compared[1]} />}
      </div>
    </details>
  )
}

function RevisionComparison({ left, right }: { left: HistoryRecord; right: HistoryRecord }) {
  const statusFor = (record: HistoryRecord, rule: string): RuleDisplayStatus => ruleStatus(record.report, rule)
  return (
    <div className="revision-comparison">
      <div className="comparison-heading">
        <h3>Revision comparison</h3>
        <div className="comparison-identities">
          {[left, right].map((record) => (
            <div className="comparison-identity" key={record.id}>
              <strong>{record.label}</strong>
              <code>{shortHash(record.identity.commit, 8)}</code>
              <code>{shortHash(record.report.source.canonical_sha256, 8)}</code>
              <span>{record.sourceMode.toUpperCase()} · {new Date(record.createdAt).toLocaleString()}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="comparison-rules">
        {RULES.map(([rule]) => {
          const before = statusFor(left, rule)
          const after = statusFor(right, rule)
          return (
            <div key={rule} className={before !== after ? 'changed' : ''}>
              <code>{rule}</code><span>{before}</span><ArrowRightIcon /><span>{after}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

export default function App() {
  const restoredShare = useMemo(readSharePayload, [])
  const initialFixture = (() => {
    if (restoredShare) return restoredShare.fixtureId
    const id = new URLSearchParams(window.location.search).get('fixture') as FixtureId | null
    return FIXTURES.some((fixture) => fixture.id === id) ? id! : 'tip-jar'
  })()
  const [fixtureId, setFixtureId] = useState<FixtureId>(initialFixture)
  const [identity, setIdentity] = useState<SourceIdentity>(() => restoredShare?.identity ?? fixtureIdentity(fixtureById(initialFixture)))
  const [sourceDigest, setSourceDigest] = useState<string | null>(null)
  const [usePreview, setUsePreview] = useState(true)
  const [report, setReport] = useState<AuditReport | null>(null)
  const [sourceMode, setSourceMode] = useState<AnalyzeResponse['source_mode'] | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [snapshotNotice, setSnapshotNotice] = useState<string | null>(restoredShare
    ? 'Shared snapshot loaded. Run analysis to reproduce its findings against the pinned source.'
    : null)
  const [activeRule, setActiveRule] = useState<string | null>('AUTH-01')
  const [history, setHistory] = useState<HistoryRecord[]>(loadHistory)
  const [comparison, setComparison] = useState<string[]>([])
  const [copied, setCopied] = useState(false)
  const [shareError, setShareError] = useState<string | null>(null)
  const [sourceOpen, setSourceOpen] = useState(true)
  const [liveMessage, setLiveMessage] = useState('Ready to analyze a pinned source revision.')
  const controller = useRef<AbortController | null>(null)
  const resultSummaryRef = useRef<HTMLDivElement | null>(null)
  const sourcePanelRef = useRef<HTMLElement | null>(null)
  const commitInputRef = useRef<HTMLInputElement | null>(null)
  const analyzeActionRef = useRef<HTMLButtonElement | null>(null)
  const focusResultAfterAnalysis = useRef(false)
  const selectedFixture = fixtureById(fixtureId)
  const sourceUrl = pinnedSourceUrl(identity)
  const activeFinding = report?.findings.find((finding) => finding.rule === activeRule) ?? null
  const expectedDigest = fixtureId === 'unverifiable' ? '0'.repeat(64) : sourceDigest

  useEffect(() => {
    let alive = true
    const timer = window.setTimeout(() => {
      sourceSha256(identity.source).then((hash) => {
        if (alive) {
          setSourceDigest(hash)
          setLiveMessage('Canonical source hash ready.')
        }
      })
    }, 180)
    return () => {
      alive = false
      window.clearTimeout(timer)
    }
  }, [identity.source])

  useEffect(() => {
    if (!report || !focusResultAfterAnalysis.current) return
    focusResultAfterAnalysis.current = false
    resultSummaryRef.current?.focus()
  }, [report])

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    params.set('fixture', fixtureId)
    window.history.replaceState(null, '', `${window.location.pathname}?${params.toString()}${window.location.hash}`)
  }, [fixtureId])

  const runAnalysis = useCallback(async (previewMode: boolean) => {
    if (!sourceDigest || !expectedDigest) return
    controller.current?.abort()
    controller.current = new AbortController()
    setLoading(true)
    setError(null)
    setLiveMessage('Analyzing the exact source revision.')
    focusResultAfterAnalysis.current = true
    try {
      const response = await analyzeRevision(sourceUrl, expectedDigest, previewMode ? identity.source : undefined, controller.current.signal)
      if (!await isReproducedResponse(identity, sourceDigest, response)) {
        throw new Error('The analyzer response could not be reproduced against this source revision and policy.')
      }
      setReport(response.report)
      setSourceMode(response.source_mode)
      setSourceOpen(false)
      setSnapshotNotice(null)
      setLiveMessage(`Local analysis complete. Overall result: ${response.report.status}.`)
      const record: HistoryRecord = {
        id: `${Date.now()}-${response.report.report_sha256}`,
        createdAt: new Date().toISOString(),
        identity: { ...identity },
        label: selectedFixture.label,
        provenance: 'reproduced',
        report: response.report,
        sourceMode: response.source_mode,
      }
      setHistory((current) => {
        const next = [record, ...current.filter((item) => item.report.report_sha256 !== record.report.report_sha256)].slice(0, 12)
        localStorage.setItem(STORAGE_KEY, JSON.stringify(next))
        return next
      })
      const firstFinding = response.report.findings[0]?.rule
      if (firstFinding) setActiveRule(firstFinding)
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === 'AbortError') return
      setError(caught instanceof Error ? caught.message : 'Analysis failed.')
      setLiveMessage(caught instanceof Error ? `Analysis failed: ${caught.message}` : 'Analysis failed.')
      setReport(null)
      setSourceMode(null)
      focusResultAfterAnalysis.current = false
    } finally {
      setLoading(false)
    }
  }, [expectedDigest, identity, selectedFixture.label, sourceDigest, sourceUrl])

  const updateIdentity = (next: SourceIdentity) => {
    controller.current?.abort()
    setSourceDigest(null)
    setLiveMessage('Source changed. Recomputing the canonical hash; the previous report was cleared.')
    setIdentity(next)
    setReport(null)
    setSourceMode(null)
    setError(null)
    setCopied(false)
    setShareError(null)
    setSnapshotNotice(null)
    setSourceOpen(true)
  }

  const selectFixture = (id: FixtureId) => {
    const fixture = fixtureById(id)
    setFixtureId(id)
    updateIdentity(fixtureIdentity(fixture))
    setUsePreview(true)
  }

  const focusSourceControl = (control: HTMLInputElement | HTMLButtonElement | null) => {
    sourcePanelRef.current?.scrollIntoView({ block: 'start' })
    control?.focus()
  }

  const usePinnedSource = () => {
    setUsePreview(false)
    setSourceOpen(false)
    setLiveMessage('Fetching and reproducing the commit-pinned source. The connected wallet remains available.')
    void runAnalysis(false)
  }

  const editSourceRevision = () => {
    setLiveMessage('Edit the full commit or another source identity field, then analyze the new revision.')
    focusSourceControl(commitInputRef.current)
    commitInputRef.current?.select()
  }

  const share = async () => {
    if (!report || !sourceMode) return
    const url = new URL(window.location.href)
    url.hash = new URLSearchParams({
      r: encodeSharePayload({ fixtureId, identity, report, sourceMode, version: 1 }),
    }).toString()
    try {
      await navigator.clipboard.writeText(url.toString())
      setShareError(null)
      setCopied(true)
      setLiveMessage('Share snapshot link copied.')
      window.setTimeout(() => setCopied(false), 1600)
    } catch {
      setCopied(false)
      setShareError('Clipboard access failed. Copy the current address from the browser.')
      setLiveMessage('Clipboard access failed. Copy the current address from the browser.')
    }
  }

  const restoreRecord = (record: HistoryRecord) => {
    setSourceDigest(null)
    setIdentity({ ...record.identity })
    setFixtureId((FIXTURES.some((fixture) => fixture.label === record.label)
      ? FIXTURES.find((fixture) => fixture.label === record.label)!.id
      : 'tip-jar'))
    setReport(record.provenance === 'reproduced' ? record.report : null)
    setSourceMode(record.provenance === 'reproduced' ? record.sourceMode : null)
    setError(null)
    setActiveRule(record.report.findings[0]?.rule ?? 'SRC-01')
    setSnapshotNotice(record.provenance === 'snapshot'
      ? 'Browser snapshot loaded. Run analysis to reproduce its findings before interpretation or comparison.'
      : null)
    setSourceOpen(record.provenance === 'snapshot')
  }

  const toggleComparison = (id: string) => {
    setComparison((current) => {
      if (current.includes(id)) return current.filter((item) => item !== id)
      return [...current.slice(-1), id]
    })
  }

  return (
    <div className="app-shell">
      <p className="sr-only" role="status" aria-live="polite" aria-atomic="true">{liveMessage}</p>
      <a className="skip-link" href="#source-title">Skip to source</a>
      {report && <a className="skip-link skip-results" href="#spectrum-title">Skip to report</a>}
      <PolicyRail activeRule={activeRule} onSelect={setActiveRule} />
      <main onKeyDown={(event) => {
        if ((event.ctrlKey || event.metaKey) && event.key === 'Enter' && !loading && sourceDigest) {
          event.preventDefault()
          void runAnalysis(usePreview)
        }
      }}>
        <header className="topbar">
          <div>
            <span className="live-dot" />
            <span>CONSENSUS SAFETY WORKBENCH</span>
          </div>
          <div className="topbar-actions">
            <span className="policy-chip">{POLICY_ID}</span>
            <button className="primary-action mobile-analyze-action" onClick={() => void runAnalysis(usePreview)} disabled={loading || !sourceDigest}>
              {loading ? <SpinnerGapIcon className="spin" /> : <PulseIcon />}
              {loading ? 'Analyzing' : report ? 'Reproduce analysis' : 'Analyze'}
            </button>
            <button onClick={share} className="icon-action" title="Copy a self-contained local snapshot link" disabled={!report || !sourceMode}>
              {copied ? <CheckIcon /> : <LinkIcon />}<span>{copied ? 'Copied' : report ? 'Share snapshot' : 'Run analysis to share'}</span>
            </button>
            {shareError && <span className="share-error" role="alert">{shareError}</span>}
          </div>
        </header>

        <FixtureStrip selected={fixtureId} onSelect={selectFixture} />

        {snapshotNotice && (
          <div className="snapshot-notice" role="status">
            <WarningCircleIcon aria-hidden="true" />
            <div><strong>Unverified local snapshot</strong><p>{snapshotNotice}</p></div>
          </div>
        )}

        <div className="responsive-rule-focus">
          <RuleFocus report={report} activeRule={activeRule} />
        </div>

        <div className={`workbench ${report ? 'has-report' : 'awaiting-report'}`}>
          <section className="source-panel" ref={sourcePanelRef} aria-labelledby="source-title">
            <div className="panel-heading">
              <div>
                <h1 id="source-title">Pin the exact contract revision</h1>
                <p>Establish source identity before interpreting any rule result.</p>
              </div>
            </div>

            <div className="source-fields">
              <label>
                <span><GithubLogoIcon /> Repository</span>
                <input value={identity.repository} onChange={(event) => updateIdentity({ ...identity, repository: event.target.value })} spellCheck="false" />
              </label>
              <label>
                <span><GitCommitIcon /> Full commit</span>
                <input ref={commitInputRef} value={identity.commit} onChange={(event) => updateIdentity({ ...identity, commit: event.target.value })} spellCheck="false" />
              </label>
              <label className="path-field">
                <span><CodeIcon /> Contract path</span>
                <input value={identity.path} onChange={(event) => updateIdentity({ ...identity, path: event.target.value })} spellCheck="false" />
              </label>
            </div>

            <div className="identity-readout">
              <div><span>PINNED RAW URL</span><ExactValue label="Pinned raw URL" value={sourceUrl} onStatus={setLiveMessage} /></div>
              <div><span>CANONICAL SHA-256</span><ExactValue label="Canonical SHA-256" value={sourceDigest || 'computing'} onStatus={setLiveMessage} /></div>
            </div>

            <div className={`source-authority ${usePreview ? 'source-authority-preview' : 'source-authority-pinned'}`} role="status">
              <div><span>ANALYZED MATERIAL</span><strong>{usePreview ? 'Bundled fixture preview' : 'Fetched pinned source'}</strong></div>
              <p>{usePreview ? 'Submitted bytes · not fetched from GitHub' : 'Remote bytes must match the pinned digest'}</p>
              <label className="source-mode-toggle">
                <input type="checkbox" checked={usePreview} onChange={(event) => {
                  setUsePreview(event.target.checked)
                  setReport(null)
                  setSourceMode(null)
                  setSourceOpen(true)
                }} />
                <span>Use bundled preview</span>
              </label>
            </div>

            <div className="identity-action-row">
              <div className="fixture-note">
                <ShieldWarningIcon aria-hidden="true" />
                <p><strong>{selectedFixture.label}</strong>{selectedFixture.note}</p>
              </div>
              <button ref={analyzeActionRef} className="primary-action analyze-action" onClick={() => void runAnalysis(usePreview)} disabled={loading || !sourceDigest}>
                {loading ? <SpinnerGapIcon className="spin" /> : <PulseIcon />}
                {loading ? 'Analyzing revision' : report ? 'Reproduce analysis' : 'Analyze revision'}
                {!loading && <ArrowRightIcon />}
              </button>
            </div>

            <details className="source-editor" open={sourceOpen} onToggle={(event) => setSourceOpen(event.currentTarget.open)}>
              <summary className="editor-toolbar">
                <span>{sourceOpen ? 'Hide contract source' : 'Review contract source'}</span>
                <code>{identity.path.split('/').at(-1) ?? 'contract.py'}</code>
              </summary>
              <textarea
                aria-label="Contract source preview"
                value={identity.source}
                onChange={(event) => updateIdentity({ ...identity, source: event.target.value })}
                spellCheck="false"
                rows={15}
              />
            </details>

            {error && (
              <div className="error-state" role="alert">
                <WarningCircleIcon />
                <div><strong>Analysis did not complete</strong><p>{error}</p></div>
                <button onClick={() => void runAnalysis(usePreview)}><ArrowClockwiseIcon /> Retry</button>
              </div>
            )}
          </section>

          {report && <div
            className="results-column"
            id="local-report"
            ref={resultSummaryRef}
            tabIndex={-1}
            aria-label={`Local analysis result: ${report.status}`}
          >
            <RuleSpectrum report={report} activeRule={activeRule} onSelect={setActiveRule} loading={loading} />
            <section className="finding-panel" aria-label="Selected rule evidence">
              <FindingReadout finding={activeFinding} activeRule={activeRule} report={report} />
              {report && (
                <div className="report-seal">
                  <div><span>LOCAL REPORT</span><strong>{report.status}</strong></div>
                  <dl>
                    <div><dt>SOURCE MODE</dt><dd>{sourceMode?.toUpperCase()}</dd></div>
                    <div><dt>SEVERITY</dt><dd>{report.severity}</dd></div>
                    <div><dt>REPORT SHA-256</dt><dd><ExactValue label="Local report SHA-256" value={report.report_sha256} onStatus={setLiveMessage} /></dd></div>
                  </dl>
                </div>
              )}
            </section>
          </div>}
        </div>

        {report && <p className="scope-statement">
          <strong>Interpretation boundary.</strong> MEETS_BASELINE means only that this revision meets the twelve implemented rules in {POLICY_ID}. It is not formal verification or a security guarantee.
        </p>}

        {report && (
          <AttestationBoundary
            analysisLoading={loading}
            report={report}
            sourceMode={sourceMode}
            onUsePinnedSource={usePinnedSource}
            onEditSourceRevision={editSourceRevision}
          />
        )}
        {history.length > 0 && <HistoryArchive records={history} selected={comparison} onToggle={toggleComparison} onRestore={restoreRecord} />}

        <footer>
          <span>EquivLab consensus safety workbench</span>
          <span>Local analysis and authoritative registry readback remain explicitly separate.</span>
        </footer>
      </main>
    </div>
  )
}
