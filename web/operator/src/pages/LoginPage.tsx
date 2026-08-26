import { useRef, useState, type FormEvent } from 'react'
import { ArrowRight, KeyRound, ShieldCheck } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../auth-context'

export function LoginPage() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const secretInput = useRef<HTMLInputElement>(null)
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    const secret = secretInput.current?.value ?? ''
    if (secretInput.current) secretInput.current.value = ''
    setError('')
    setSubmitting(true)
    try {
      await login(secret)
      navigate('/', { replace: true })
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Authentication failed.')
      secretInput.current?.focus()
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main className="login-page">
      <section className="login-panel">
        <div className="login-brand">
          <span className="brand-mark brand-mark-dark" aria-hidden="true"><i /><i /><i /></span>
          <strong>STORM / OPERATOR</strong>
        </div>
        <div className="login-copy">
          <span className="eyebrow">Restricted network access</span>
          <h1>Enter the operator workspace.</h1>
          <p>Authenticate against this node with your registered operator key.</p>
        </div>
        <form className="login-form" onSubmit={submit}>
          <label htmlFor="secret-key">Operator secret key</label>
          <div className="secret-field">
            <KeyRound size={19} aria-hidden="true" />
            <input ref={secretInput} id="secret-key" type="text" autoComplete="off"
              autoCapitalize="none" spellCheck={false} placeholder="64-character hex key"
              aria-describedby="secret-note" required />
          </div>
          <div className="form-footnote" id="secret-note">
            <ShieldCheck size={15} /><span>Held in this tab's memory until logout.</span>
          </div>
          {error && <div className="form-error" role="alert">{error}</div>}
          <button className="primary-button login-button" disabled={submitting}>
            <span>{submitting ? 'Signing challenge…' : 'Authenticate'}</span><ArrowRight size={18} />
          </button>
        </form>
        <div className="login-meta"><span>HIGH-STORM</span><span>BIP322 / MAINNET</span></div>
      </section>

      <section className="login-visual" aria-label="Storm network status graphic">
        <div className="topology">
          <span className="topology-label">ORACLE NETWORK</span>
          <svg className="topology-links" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
            <line x1="22" y1="30" x2="78" y2="24" />
            <line x1="22" y1="30" x2="36" y2="72" />
            <line x1="36" y1="72" x2="72" y2="62" />
          </svg>
          <span className="topology-node node-a">01</span><span className="topology-node node-b">02</span>
          <span className="topology-node node-c">03</span><span className="topology-node node-d">04</span>
          <div className="topology-caption"><strong>Consensus is operational.</strong><span>Signed access only</span></div>
        </div>
      </section>
    </main>
  )
}