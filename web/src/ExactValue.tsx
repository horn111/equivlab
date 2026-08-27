import { useState } from 'react'
import { CheckIcon } from '@phosphor-icons/react/Check'
import { CopyIcon } from '@phosphor-icons/react/Copy'
import { EyeIcon } from '@phosphor-icons/react/Eye'
import { EyeSlashIcon } from '@phosphor-icons/react/EyeSlash'

interface Props {
  label: string
  onStatus?: (message: string) => void
  value: string
}

export default function ExactValue({ label, onStatus, value }: Props) {
  const [revealed, setRevealed] = useState(false)
  const [copied, setCopied] = useState(false)

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      onStatus?.(`${label} copied.`)
      window.setTimeout(() => setCopied(false), 1600)
    } catch {
      setCopied(false)
      onStatus?.(`Could not copy ${label.toLowerCase()}. Select the revealed value instead.`)
    }
  }

  return (
    <div className={`exact-value ${revealed ? 'exact-value-revealed' : ''}`}>
      <code title={revealed ? undefined : value}>{value}</code>
      <div className="exact-value-actions">
        <button
          type="button"
          className="exact-value-action"
          aria-expanded={revealed}
          aria-label={`${revealed ? 'Hide' : 'Reveal'} ${label.toLowerCase()}`}
          onClick={() => setRevealed((current) => !current)}
        >
          {revealed ? <EyeSlashIcon aria-hidden="true" /> : <EyeIcon aria-hidden="true" />}
          <span>{revealed ? 'Hide' : 'Reveal'}</span>
        </button>
        <button
          type="button"
          className="exact-value-action"
          aria-label={`Copy ${label.toLowerCase()}`}
          onClick={copy}
        >
          {copied ? <CheckIcon aria-hidden="true" /> : <CopyIcon aria-hidden="true" />}
          <span>{copied ? 'Copied' : 'Copy'}</span>
        </button>
      </div>
    </div>
  )
}
