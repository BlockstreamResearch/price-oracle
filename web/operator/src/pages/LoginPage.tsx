import { useState, type FormEvent } from 'react'
import { ArrowRight, ShieldCheck, WalletCards } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../auth-context'

export function LoginPage() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError('')
    setSubmitting(true)
    try {
      await login()
      navigate('/', { replace: true })
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Authentication failed.')
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
          <p>Connect Humid and approve a signature with your registered operator account.</p>
        </div>
        <form className="login-form" onSubmit={submit}>
          <div className="form-footnote" id="secret-note">
            <ShieldCheck size={15} /><span>Your private key stays inside Humid.</span>
          </div>
          {error && <div className="form-error" role="alert">{error}</div>}
          <button className="primary-button login-button" disabled={submitting}>
            <WalletCards size={18} />
            <span>{submitting ? 'Waiting for Humid…' : 'Connect Humid'}</span><ArrowRight size={18} />
          </button>
        </form>
        <div className="login-meta"><span>HIGH-STORM</span><span>HUMID / ELEMENTS</span></div>
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