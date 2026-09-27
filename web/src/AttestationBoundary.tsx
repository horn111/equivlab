import { useCallback, useEffect, useMemo, useState } from 'react'
import { ArrowClockwiseIcon } from '@phosphor-icons/react/ArrowClockwise'
import { ArrowSquareOutIcon } from '@phosphor-icons/react/ArrowSquareOut'
import { GitCommitIcon } from '@phosphor-icons/react/GitCommit'
import { SealCheckIcon } from '@phosphor-icons/react/SealCheck'
import { SpinnerGapIcon } from '@phosphor-icons/react/SpinnerGap'
import { WalletIcon } from '@phosphor-icons/react/Wallet'
import { WarningCircleIcon } from '@phosphor-icons/react/WarningCircle'
import type { TransactionHash, TransactionStatus } from 'genlayer-js/types'
import {
  createGenLayerReadClient,
  createGenLayerWriteClient,
  ensureWalletNetwork,
  isSuccessfulExecution,
  isUndeterminedReceipt,
  readAuthoritativeAudit,
  readLatestRegistryAudit,
  resolveGenLayerConfig,
  transactionExplorerUrl,
  walletErrorMessage,
  type RegistryAddress,
} from './genlayer'
import ExactValue from './ExactValue'
import type { AnalyzeResponse, AuditReport, OnChainReadback } from './types'

const PENDING_KEY = 'equivlab:pending-attestation:v1'
const ACCEPTED = 'ACCEPTED' as TransactionStatus
const FINALIZED = 'FINALIZED' as TransactionStatus

function sameRuleOutcomes(local: AuditReport, registry: AuditReport): boolean {
  return local.status === registry.status
    && local.severity === registry.severity
    && (['implemented_rules', 'failed_rules', 'warning_rules', 'unverifiable_rules'] as const).every(
      (field) => [...local[field]].sort().join('\n') === [...registry[field]].sort().join('\n'),
    )
}

function outcomeSummary(report: AuditReport): string {
  return `${report.status} · ${report.severity}. Rules checked: ${report.implemented_rules.join(', ')}. Failed: ${report.failed_rules.join(', ') || 'none'}. Warnings: ${report.warning_rules.join(', ') || 'none'}. Unverifiable: ${report.unverifiable_rules.join(', ') || 'none'}.`
}

type LifecycleStage =
  | 'idle'
  | 'connecting'
  | 'ready'
  | 'signing'
  | 'submitted'
  | 'consensus'
  | 'finalizing'
  | 'readback'
  | 'complete'
  | 'undetermined'
  | 'error'

interface PendingAttestation {
  network: string
  policy: string
  registryAddress: string
  sourceHash: string
  sourceUrl: string
  transactionHash: TransactionHash
}

interface Props {
  analysisLoading: boolean
  onEditSourceRevision: () => void
  onUsePinnedSource: () => void
  report: AuditReport
  sourceMode: AnalyzeResponse['source_mode'] | null
}

const STAGE_COPY: Record<LifecycleStage, string> = {
  idle: 'No on-chain request has been made.',
  connecting: 'Waiting for wallet and network authorization.',
  ready: 'Wallet ready. No transaction has been sent.',
  signing: 'Waiting for the wallet signature.',
  submitted: 'Transaction submitted. Consensus has not been confirmed.',
  consensus: 'Waiting for a decided validator result.',
  finalizing: 'Consensus accepted. Waiting for finalization.',
  readback: 'Finalized. Reading the registry as a separate authority.',
  complete: 'Authoritative registry readback matches the pinned source identity.',
  undetermined: 'The network reached a terminal non-authoritative state. No attestation is claimed.',
  error: 'The lifecycle stopped before authoritative readback. Reconciliation remains available.',
}

const STEP_ORDER = ['submitted', 'consensus', 'finalizing', 'readback', 'complete'] as const

function pendingMatches(value: PendingAttestation, report: AuditReport, network: string, registryAddress: string): boolean {
  return value.network === network
    && value.registryAddress.toLowerCase() === registryAddress.toLowerCase()
    && value.policy === report.policy
    && value.sourceHash === report.source.canonical_sha256
    && value.sourceUrl === report.source.url
    && /^0x[0-9a-fA-F]{64}$/.test(value.transactionHash)
}

function stagePosition(stage: LifecycleStage): number {
  if (stage === 'complete') return STEP_ORDER.length
  const position = STEP_ORDER.indexOf(stage as (typeof STEP_ORDER)[number])
  return position < 0 ? -1 : position
}

export default function AttestationBoundary({ analysisLoading, onEditSourceRevision, onUsePinnedSource, report, sourceMode }: Props) {
  const resolution = useMemo(() => resolveGenLayerConfig(import.meta.env), [])
  const config = resolution.config
  const [account, setAccount] = useState<RegistryAddress | null>(null)
  const [stage, setStage] = useState<LifecycleStage>('idle')
  const [error, setError] = useState<string | null>(resolution.error)
  const [transactionHash, setTransactionHash] = useState<TransactionHash | null>(null)
  const [readback, setReadback] = useState<OnChainReadback | null>(null)
  const [readbackAuthority, setReadbackAuthority] = useState<'registry-observed' | 'finalized' | null>(null)
  const [existingLookup, setExistingLookup] = useState<'idle' | 'checking' | 'none' | 'found' | 'error'>('idle')
  const [lookupError, setLookupError] = useState<string | null>(null)
  const [announcement, setAnnouncement] = useState('')
  const [supersedesId, setSupersedesId] = useState('')
  const [challengeReasonHash, setChallengeReasonHash] = useState('')
  const [challengeTransactionHash, setChallengeTransactionHash] = useState<TransactionHash | null>(null)
  const [challengeBusy, setChallengeBusy] = useState(false)

  const lookupExisting = useCallback(async () => {
    if (!config || sourceMode !== 'retrieved') return
    setLookupError(null)
    setExistingLookup('checking')
    setAnnouncement('Checking the registry for an existing audit of this exact source identity.')
    try {
      const client = await createGenLayerReadClient(config)
      const existing = await readLatestRegistryAudit(
        client,
        config,
        report.source.canonical_sha256,
        report.source.url,
        report.policy,
      )
      if (existing) {
        setReadback(existing)
        setReadbackAuthority('registry-observed')
        setExistingLookup('found')
        setStage('complete')
        setAnnouncement(`Existing registry audit ${existing.audit.id} loaded. Finalization was not independently checked. Result: ${existing.report.status}.`)
      } else {
        setReadback(null)
        setReadbackAuthority(null)
        setExistingLookup('none')
        setStage('idle')
        setAnnouncement('No existing audit was found for this exact source identity and policy.')
      }
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : 'Registry lookup failed.'
      setReadback(null)
      setReadbackAuthority(null)
      setExistingLookup('error')
      setLookupError(message)
      setStage('idle')
      setAnnouncement(`Registry lookup failed: ${message}`)
    }
  }, [config, report, sourceMode])

  useEffect(() => {
    setTransactionHash(null)
    setReadback(null)
    setReadbackAuthority(null)
    setExistingLookup('idle')
    setLookupError(null)
    if (!config || sourceMode !== 'retrieved') return
    try {
      const raw = localStorage.getItem(PENDING_KEY)
      if (raw) {
        const pending = JSON.parse(raw) as PendingAttestation
        if (pendingMatches(pending, report, config.network, config.registryAddress)) {
          setTransactionHash(pending.transactionHash)
          setStage('submitted')
          setAnnouncement('A pending attestation transaction was restored. Reconcile it to continue.')
          return
        }
      }
    } catch {
      localStorage.removeItem(PENDING_KEY)
    }
    void lookupExisting()
  }, [config, lookupExisting, report, sourceMode])

  const connectWallet = useCallback(async () => {
    if (!config) return
    if (!window.ethereum) {
      setError('No injected EVM wallet was found. Open EquivLab in a desktop browser with MetaMask or Rabby enabled.')
      setStage('error')
      return
    }
    setError(null)
    setStage('connecting')
    try {
      const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' })
      if (!Array.isArray(accounts) || typeof accounts[0] !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(accounts[0])) {
        throw new Error('The wallet returned no canonical account address.')
      }
      const nextAccount = accounts[0] as RegistryAddress
      await ensureWalletNetwork(config, window.ethereum)
      setAccount(nextAccount)
      setStage('ready')
      setAnnouncement(`Wallet ${nextAccount} connected.`)
    } catch (caught) {
      setError(walletErrorMessage(caught, 'Wallet connection failed.'))
      setStage('error')
    }
  }, [config])

  const reconcile = useCallback(async (hash: TransactionHash) => {
    if (!config) return
    setError(null)
    setReadback(null)
    setReadbackAuthority(null)
    setTransactionHash(hash)
    try {
      const client = await createGenLayerReadClient(config)
      setStage('consensus')
      const accepted = await client.waitForTransactionReceipt({
        hash,
        status: ACCEPTED,
        interval: 5_000,
        retries: 120,
      })
      if (isUndeterminedReceipt(accepted)) {
        setError(`Transaction ended as ${accepted.statusName ?? 'UNDETERMINED'}. The registry was not treated as authoritative.`)
        setStage('undetermined')
        return
      }
      if (!isSuccessfulExecution(accepted)) {
        throw new Error(`Contract execution did not return successfully (${accepted.txExecutionResultName ?? 'execution result unavailable'}).`)
      }

      let finalized = accepted
      if (accepted.statusName !== FINALIZED) {
        setStage('finalizing')
        finalized = await client.waitForTransactionReceipt({
          hash,
          status: FINALIZED,
          interval: 5_000,
          retries: 200,
        })
      }
      if (!isSuccessfulExecution(finalized)) {
        throw new Error(`Finalized transaction did not return successfully (${finalized.txExecutionResultName ?? 'execution result unavailable'}).`)
      }

      setStage('readback')
      const authoritative = await readAuthoritativeAudit(
        client,
        config,
        report.source.canonical_sha256,
        report.source.url,
        report.policy,
        hash,
      )
      setReadback(authoritative)
      setReadbackAuthority('finalized')
      setExistingLookup('found')
      localStorage.removeItem(PENDING_KEY)
      setStage('complete')
      setAnnouncement(`Authoritative audit ${authoritative.audit.id} loaded. Result: ${authoritative.report.status}.`)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Transaction reconciliation failed.')
      setStage('error')
    }
  }, [config, report])

  const requestAttestation = useCallback(async () => {
    if (!config || !account || !window.ethereum) return
    if (sourceMode !== 'retrieved') {
      setError('Fetch and reproduce the pinned GitHub source before requesting an attestation.')
      return
    }
    if (!/^(|0|[1-9][0-9]*)$/.test(supersedesId.trim())) {
      setError('Supersedes ID must be empty or a canonical decimal audit ID.')
      return
    }

    setError(null)
    setReadback(null)
    setStage('signing')
    try {
      await ensureWalletNetwork(config, window.ethereum)
      const client = await createGenLayerWriteClient(config, account, window.ethereum)
      const supersededAuditId = supersedesId.trim()
      const submitted = await client.writeContract({
        address: config.registryAddress,
        functionName: supersededAuditId ? 'request_superseding_audit' : 'request_audit',
        args: supersededAuditId
          ? [report.source.url, report.source.canonical_sha256, report.policy, BigInt(supersededAuditId)]
          : [report.source.url, report.source.canonical_sha256, report.policy],
        value: 0n,
      })
      if (typeof submitted !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(submitted)) {
        throw new Error('The wallet did not return a canonical transaction hash.')
      }
      const hash = submitted as TransactionHash
      const pending: PendingAttestation = {
        network: config.network,
        policy: report.policy,
        registryAddress: config.registryAddress,
        sourceHash: report.source.canonical_sha256,
        sourceUrl: report.source.url,
        transactionHash: hash,
      }
      localStorage.setItem(PENDING_KEY, JSON.stringify(pending))
      setTransactionHash(hash)
      setStage('submitted')
      setAnnouncement(`Attestation transaction ${hash} submitted.`)
      await reconcile(hash)
    } catch (caught) {
      setError(walletErrorMessage(caught, 'Attestation transaction was not submitted.'))
      setStage('error')
    }
  }, [account, config, reconcile, report, sourceMode, supersedesId])

  const challengeAttestation = useCallback(async () => {
    if (!config || !account || !window.ethereum || !readback) return
    const reasonHash = challengeReasonHash.trim().toLowerCase().replace(/^sha256:/, '')
    if (!/^[0-9a-f]{64}$/.test(reasonHash)) {
      setError('Challenge reason must be a canonical SHA-256 hash.')
      return
    }
    setError(null)
    setChallengeBusy(true)
    try {
      await ensureWalletNetwork(config, window.ethereum)
      const writeClient = await createGenLayerWriteClient(config, account, window.ethereum)
      const submitted = await writeClient.writeContract({
        address: config.registryAddress,
        functionName: 'challenge',
        args: [BigInt(readback.audit.id), reasonHash],
        value: 0n,
      })
      if (typeof submitted !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(submitted)) {
        throw new Error('The wallet did not return a canonical challenge transaction hash.')
      }
      const hash = submitted as TransactionHash
      setChallengeTransactionHash(hash)
      const readClient = await createGenLayerReadClient(config)
      const receipt = await readClient.waitForTransactionReceipt({
        hash,
        status: FINALIZED,
        interval: 5_000,
        retries: 200,
      })
      if (!isSuccessfulExecution(receipt)) {
        throw new Error(`Challenge execution did not return successfully (${receipt.txExecutionResultName ?? 'execution result unavailable'}).`)
      }
      const updated = await readLatestRegistryAudit(
        readClient,
        config,
        report.source.canonical_sha256,
        report.source.url,
        report.policy,
        readback.transactionHash,
      )
      if (!updated) throw new Error('The challenged audit could not be read back from the registry.')
      setReadback(updated)
      setChallengeReasonHash('')
      setAnnouncement(`Challenge finalized for audit ${updated.audit.id}.`)
    } catch (caught) {
      setError(walletErrorMessage(caught, 'Challenge transaction failed.'))
    } finally {
      setChallengeBusy(false)
    }
  }, [account, challengeReasonHash, config, readback, report])

  const explorerUrl = config && transactionHash ? transactionExplorerUrl(config, transactionHash) : null
  const challengeExplorerUrl = config && challengeTransactionHash ? transactionExplorerUrl(config, challengeTransactionHash) : null
  const currentPosition = stagePosition(stage)
  const outcomesMatch = readback ? sameRuleOutcomes(report, readback.report) : false
  const reportHashesMatch = readback?.report.report_sha256 === report.report_sha256
  const busy = existingLookup === 'checking' || ['connecting', 'signing', 'consensus', 'finalizing', 'readback'].includes(stage)
  const authorityCopy = existingLookup === 'checking'
    ? 'Checking this exact source identity against the registry.'
    : existingLookup === 'none'
      ? 'No existing audit for this exact source identity and policy.'
      : existingLookup === 'found'
        ? readbackAuthority === 'finalized'
          ? STAGE_COPY.complete
          : 'Registry record matches the exact source identity. Finalization was not independently checked.'
        : existingLookup === 'error'
          ? 'Registry lookup failed. No absence claim is made.'
          : config ? STAGE_COPY[stage] : 'SEPARATE AUTHORITY · NO ON-CHAIN RECORD'

  return (
    <section className={`attestation-boundary ${config ? 'attestation-configured' : 'attestation-unconfigured'}`} aria-labelledby="attestation-title">
      <p className="sr-only" role="status" aria-live="polite" aria-atomic="true">{announcement}</p>
      <div className="attestation-copy">
        <h2 id="attestation-title" tabIndex={-1}>GenLayer review</h2>
        <p>{config
          ? 'Request an on-chain audit of the pinned source. GenLayer validators reproduce the checks; the result is authoritative only after finalization and a matching registry readback.'
          : 'GenLayer review stays unavailable until a supported network and deployed registry address are configured.'}</p>
      </div>

      <dl className="network-readout">
        <div><dt>NETWORK</dt><dd>{config?.network ?? 'NOT CONFIGURED'}</dd></div>
        <div><dt>REGISTRY</dt><dd>{config ? <ExactValue label="Registry address" value={config.registryAddress} onStatus={setAnnouncement} /> : 'NOT CONFIGURED'}</dd></div>
        <div><dt>WALLET</dt><dd>{account ? <ExactValue label="Wallet address" value={account} onStatus={setAnnouncement} /> : 'NOT CONNECTED'}</dd></div>
      </dl>

      <div className="boundary-actions">
        <span className="authority-state">{authorityCopy}</span>
        {config && !account && (
          <button className="secondary-action" onClick={connectWallet} disabled={busy}>
            {stage === 'connecting' ? <SpinnerGapIcon className="spin" /> : <WalletIcon />}
            {stage === 'connecting' ? 'Authorizing wallet' : readback ? 'Connect wallet to challenge' : 'Connect wallet'}
          </button>
        )}
        {config && account && sourceMode === 'retrieved' && !transactionHash && existingLookup === 'none' && (
          <button className="primary-action" onClick={requestAttestation} disabled={busy}>
            {stage === 'signing' ? <SpinnerGapIcon className="spin" /> : <SealCheckIcon />}
            {stage === 'signing' ? 'Awaiting signature' : 'Request GenLayer review'}
          </button>
        )}
        {config && transactionHash && stage !== 'complete' && (
          <button className="secondary-action" onClick={() => reconcile(transactionHash)} disabled={busy}>
            {busy ? <SpinnerGapIcon className="spin" /> : <ArrowClockwiseIcon />}
            {busy ? 'Reconciling' : 'Reconcile transaction'}
          </button>
        )}
      </div>

      {config && sourceMode === 'retrieved' && !transactionHash && existingLookup === 'none' && (
        <div className="review-instructions">
          <strong>Start a new GenLayer review</strong>
          <ol>
            <li>Connect Rabby or MetaMask on desktop with GEN on Bradbury testnet.</li>
            <li>Select <b>Request GenLayer review</b> and confirm the transaction in your wallet. Network fees apply.</li>
            <li>Follow consensus and finalization here, then inspect the source-matched registry result.</li>
          </ol>
          <p>Connecting your wallet does not send a transaction.</p>
        </div>
      )}

      {config && sourceMode !== 'retrieved' && (
        <div className="registry-guidance" role="status">
          <div>
            <strong>Pinned source required</strong>
            <p>This report used submitted editor bytes. Retrieve and reproduce the exact commit-pinned source before requesting a GenLayer review. You do not need to connect a wallet for this step.</p>
          </div>
          <button className="secondary-action" type="button" onClick={onUsePinnedSource} disabled={analysisLoading}>
            {analysisLoading ? <SpinnerGapIcon className="spin" /> : <ArrowClockwiseIcon />}
            {analysisLoading ? 'Retrieving source' : 'Retrieve pinned source'}
          </button>
        </div>
      )}

      {readback && (
        <div className="registry-guidance">
          <div>
            <strong>This revision already has a GenLayer review</strong>
            <p>Audit {readback.audit.id} covers this exact source URL, hash, and policy. No new transaction is needed to read it below. Duplicate requests are not accepted.</p>
            <p>To trigger a new review, use your own public contract or a new full commit, analyze its pinned source, then connect your wallet and select Request GenLayer review.</p>
          </div>
          <button className="secondary-action" type="button" onClick={onEditSourceRevision}>
            <GitCommitIcon /> Analyze a new revision
          </button>
        </div>
      )}

      {config && account && sourceMode === 'retrieved' && !transactionHash && existingLookup === 'none' && (
        <label className="supersedes-field">
          <span>SUPERSEDES AUDIT ID · OPTIONAL</span>
          <input
            inputMode="numeric"
            pattern="[0-9]*"
            value={supersedesId}
            onChange={(event) => setSupersedesId(event.target.value)}
            placeholder="Leave empty for a new source history"
          />
        </label>
      )}

      {config && transactionHash && (
        <div className="transaction-evidence" aria-live="polite">
          <div className="transaction-identity">
            <span>TRANSACTION</span>
            <ExactValue label="Transaction hash" value={transactionHash} onStatus={setAnnouncement} />
            {explorerUrl && <a href={explorerUrl} target="_blank" rel="noreferrer">Open explorer <ArrowSquareOutIcon /></a>}
          </div>
          <ol className="transaction-lifecycle" aria-label="Attestation transaction lifecycle">
            {STEP_ORDER.map((step, index) => {
              const state = currentPosition > index ? 'complete' : currentPosition === index ? 'active' : 'pending'
              return <li className={`lifecycle-${state}`} key={step}><span aria-hidden="true" />{STAGE_COPY[step]}</li>
            })}
          </ol>
        </div>
      )}

      {readback && (
        <section
          className="authoritative-readback"
          aria-label={readbackAuthority === 'finalized' ? 'Finalized authoritative registry readback' : 'Existing registry readback'}
        >
          <div className="readback-heading">
            <span>{readbackAuthority === 'finalized' ? 'FINALIZED AUTHORITATIVE READBACK' : 'ALREADY REGISTERED'}</span>
            <strong className={`status-${readback.report.status.toLowerCase()}`}>{readback.report.status}</strong>
            {readbackAuthority !== 'finalized' && <small>AUDIT {readback.audit.id} · FINALIZATION NOT INDEPENDENTLY CHECKED</small>}
          </div>
          <dl>
            <div><dt>AUDIT ID</dt><dd>{readback.audit.id}</dd></div>
            <div><dt>REGISTRY REPORT SHA-256</dt><dd><ExactValue label="Registry report SHA-256" value={readback.report.report_sha256} onStatus={setAnnouncement} /></dd></div>
            <div><dt>REQUESTER</dt><dd><ExactValue label="Requester address" value={readback.audit.requester} onStatus={setAnnouncement} /></dd></div>
            <div><dt>CHALLENGED</dt><dd>{readback.audit.challenged ? 'YES' : 'NO'}</dd></div>
          </dl>
          <div className={`report-comparison ${outcomesMatch ? '' : 'report-comparison-different'}`} role={outcomesMatch ? 'note' : 'alert'}>
            <strong>{!outcomesMatch
              ? 'Local and registry rule outcomes differ'
              : reportHashesMatch ? 'Local and registry report hashes match' : 'Rule outcomes match; report hashes differ'}</strong>
            <p>{!outcomesMatch
              ? 'These reports cover the same source and policy, but differ in rule coverage, outcomes, or severity. Compare the results before using this audit.'
              : reportHashesMatch
                ? 'The local precheck and registry record have the same report fingerprint.'
                : 'The local precheck and registry produce separate reports. Each SHA-256 covers the full report, including evidence and descriptions. Matching rule outcomes do not require identical report text.'}</p>
            {!outcomesMatch && <>
              <p><b>Local:</b> {outcomeSummary(report)}</p>
              <p><b>Registry:</b> {outcomeSummary(readback.report)}</p>
            </>}
          </div>
          {account && (
            <details className="challenge-disclosure">
              <summary>Challenge this registry record</summary>
              <p>Submit a SHA-256 hash that commits to your challenge reason. This appends a challenge record; it does not replace the audit.</p>
              <div className="challenge-control">
                <label>
                  <span>CHALLENGE REASON SHA-256</span>
                  <input value={challengeReasonHash} onChange={(event) => setChallengeReasonHash(event.target.value)} placeholder="64 lowercase hexadecimal characters" />
                </label>
                <button className="secondary-action" onClick={challengeAttestation} disabled={challengeBusy}>
                  {challengeBusy ? <SpinnerGapIcon className="spin" /> : <WarningCircleIcon />}
                  {challengeBusy ? 'Finalizing challenge' : readback.audit.challenged ? 'Record another challenge' : 'Record challenge'}
                </button>
              </div>
            </details>
          )}
          {challengeExplorerUrl && <a className="challenge-link" href={challengeExplorerUrl} target="_blank" rel="noreferrer">Challenge transaction <ArrowSquareOutIcon /></a>}
        </section>
      )}

      {lookupError && (
        <div className="registry-lookup-error" role="alert">
          <WarningCircleIcon aria-hidden="true" />
          <span>Registry lookup failed: {lookupError}</span>
          <button className="secondary-action" type="button" onClick={() => void lookupExisting()}>Retry registry lookup</button>
        </div>
      )}
      {error && <p className="inline-error" role="alert"><WarningCircleIcon aria-hidden="true" />{error}</p>}
    </section>
  )
}
