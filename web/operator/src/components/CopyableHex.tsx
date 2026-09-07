import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { shortKey } from '../format'

type CopyableHexProps = {
  value: string
  visible?: number
  label?: string
}

export function CopyableHex({ value, visible, label = 'hex value' }: CopyableHexProps) {
  const [copied, setCopied] = useState(false)

  async function copy() {
    await navigator.clipboard.writeText(value)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1200)
  }

  const action = copied ? `Copied full ${label}` : `Copy full ${label}`

  return <button className="copyable-hex" type="button" title={action} aria-label={action} onClick={() => void copy()}>
    <code>{shortKey(value, visible)}</code>
    {copied ? <Check size={13} aria-hidden="true" /> : <Copy size={13} aria-hidden="true" />}
  </button>
}