import { useEffect, useState, type FormEvent } from 'react'
import { ArrowRight, CheckCircle2, Clock3, Coins, RefreshCw, TriangleAlert } from 'lucide-react'
import { ApiError, authenticatedGet, signedPost } from '../api'
import { useAuth } from '../auth-context'
import { CopyableHex } from '../components/CopyableHex'
import { formatNumber } from '../format'
import type { DropletsState, OperatorSession } from '../types'

function fetchDroplets(session: OperatorSession) {
  return authenticatedGet<DropletsState>(session, '/operators/droplets')
}

export function DropletsPage() {
  const { session, logout } = useAuth()
  const [state, setState] = useState<DropletsState | null>(null)
  const [amount, setAmount] = useState('')
  const [address, setAddress] = useState('')
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const parsedAmount = Number(amount)
  const validAmount = Number.isSafeInteger(parsedAmount) && parsedAmount > 0
  const totalRequired = validAmount && state && Number.isSafeInteger(parsedAmount + state.exchange_fee_sats)
    ? parsedAmount + state.exchange_fee_sats
    : null
  const insufficientBalance = totalRequired !== null && state !== null && totalRequired > state.amount

  async function load() {
    if (!session) return
    setLoading(true)
    setError('')
    try { setState(await fetchDroplets(session)) }
    catch (cause) {
      if (cause instanceof ApiError && cause.status === 401) logout()
      else setError(cause instanceof Error ? cause.message : 'Could not load Droplets state.')
    } finally { setLoading(false) }
  }

  useEffect(() => {
    if (!session) return
    let active = true
    const refresh = () => fetchDroplets(session)
      .then((nextState) => { if (active) setState(nextState) })
      .catch((cause: unknown) => {
        if (!active) return
        if (cause instanceof ApiError && cause.status === 401) logout()
        else setError(cause instanceof Error ? cause.message : 'Could not load Droplets state.')
      })
      .finally(() => { if (active) setLoading(false) })
    void refresh()
    const interval = window.setInterval(refresh, 10_000)
    return () => { active = false; window.clearInterval(interval) }
  }, [session, logout])

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!session) return
    if (!validAmount) {
      setError('Enter a positive whole number of satoshis.')
      return
    }
    if (insufficientBalance) {
      setError('Available Droplets must cover the recipient amount and transaction fee.')
      return
    }
    setSubmitting(true)
    setError('')
    try {
      const nextState = await signedPost<DropletsState>(session, '/operators/droplets/exchange', {
        amount: parsedAmount,
        address: address.trim(),
      })
      setState(nextState)
      setAmount('')
      setAddress('')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not queue the exchange.')
    } finally { setSubmitting(false) }
  }

  const request = state?.request
  const statusIcon = request?.status === 'completed'
    ? <CheckCircle2 size={17} />
    : request?.status === 'failed'
      ? <TriangleAlert size={17} />
      : <Clock3 size={17} />

  return <div className="page droplets-page">
    <header className="page-header"><div><span className="eyebrow">Treasury settlement</span><h1>Droplets</h1>
      <p>Queue an LBTC payment for execution during this node&apos;s leadership turn.</p></div>
      <button className="secondary-button" type="button" onClick={() => void load()} disabled={loading}>
        <RefreshCw size={16} className={loading ? 'spin' : ''} /> Refresh
      </button>
    </header>
    {error && <div className="page-error" role="alert">{error}</div>}

    <section className="droplets-summary" aria-label="Droplets account status">
      <div><span>Available balance</span><strong>{state ? formatNumber(state.amount) : '—'}</strong><small>satoshis</small></div>
      <div><span>Indexed block</span><strong>{state ? formatNumber(state.block_height) : '—'}</strong><small>current network state</small></div>
      <div><span>Next leadership</span><strong>{state?.next_leader_block != null ? formatNumber(state.next_leader_block) : '—'}</strong>
        <small>{state?.next_leader_block === state?.block_height ? 'active now' : 'scheduled block'}</small></div>
    </section>

    <section className="exchange-layout">
      <form className="exchange-form" onSubmit={submit}>
        <div className="section-heading"><div><span className="eyebrow">New request</span><h2>Queue exchange</h2></div>
          <Coins size={22} aria-hidden="true" /></div>
        <div className="exchange-fields">
          <label>Recipient amount<input type="number" inputMode="numeric" min="1" step="1" value={amount}
            onChange={(event) => setAmount(event.target.value)} placeholder="Amount in satoshis" required /></label>
          <label>Destination address<input value={address} onChange={(event) => setAddress(event.target.value)}
            autoComplete="off" spellCheck={false} placeholder="Unconfidential Elements address" required /></label>
          <div className={`exchange-fee-warning${insufficientBalance ? ' insufficient' : ''}`} role="status">
            <TriangleAlert size={18} aria-hidden="true" />
            <div><strong>Transaction fee: {state ? formatNumber(state.exchange_fee_sats) : '—'} satoshis</strong>
              <span>{totalRequired !== null ? `${formatNumber(totalRequired)} total Droplets required. ` : ''}
                The fee is paid to the Elements network</span></div>
          </div>
        </div>
        <footer className="exchange-actions"><span>Submission is signed by the authenticated operator key.</span>
          <button className="primary-button" disabled={submitting || state?.exchange_locked || insufficientBalance}>
            {submitting ? 'Registering…' : 'Register exchange'}<ArrowRight size={17} /></button></footer>
      </form>

      <aside className="exchange-status">
        <div className="section-heading"><div><span className="eyebrow">Execution</span><h2>Latest request</h2></div></div>
        {request ? <div className="request-detail">
          <span className={`request-state ${request.status}`}>{statusIcon}{request.status}</span>
          <dl><div><dt>Registered</dt><dd>Block {formatNumber(request.requested_at_block)}</dd></div>
            <div><dt>Amount</dt><dd>{formatNumber(request.amount)} satoshis</dd></div>
            {request.completed_txid && <div><dt>Transaction</dt><dd><CopyableHex value={request.completed_txid} visible={9} label="transaction ID" /></dd></div>}
          </dl>
          {request.last_error && <p className="request-error">{request.last_error}</p>}
          {request.status === 'pending' && <p className="request-note">The node will invoke this request only when selected as block leader.</p>}
        </div> : <div className="exchange-empty"><Clock3 size={24} /><strong>No exchange registered</strong><span>The latest request will appear here.</span></div>}
      </aside>
    </section>

    <section className="exchange-history">
      <div className="section-heading"><div><span className="eyebrow">Archive</span><h2>Previous requests</h2></div>
        <span className="history-count">{state ? formatNumber(state.history.length) : '—'} shown</span></div>
      {state?.history.length ? <table className="history-table">
        <thead><tr><th>Status</th><th>Amount</th><th>Registered</th><th>Result</th></tr></thead>
        <tbody>{state.history.map((entry) => <tr key={entry.id}>
          <td data-label="Status"><span className={`request-state ${entry.status}`}>
            {entry.status === 'completed' ? <CheckCircle2 size={15} /> : entry.status === 'failed' ? <TriangleAlert size={15} /> : <Clock3 size={15} />}
            {entry.status}</span></td>
          <td data-label="Amount">{formatNumber(entry.amount)} satoshis</td>
          <td data-label="Registered">Block {formatNumber(entry.requested_at_block)}</td>
          <td data-label="Result" className="history-result">
            {entry.completed_txid ? <CopyableHex value={entry.completed_txid} visible={10} label="transaction ID" />
              : entry.last_error ? <span title={entry.last_error}>{entry.last_error}</span> : 'Awaiting leadership'}
          </td>
        </tr>)}</tbody>
      </table> : <div className="history-empty">Completed and replaced requests will appear here.</div>}
    </section>
  </div>
}