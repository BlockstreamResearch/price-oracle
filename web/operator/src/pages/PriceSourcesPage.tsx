import { useEffect, useState } from 'react'
import { Play, RefreshCw, Snowflake } from 'lucide-react'
import { ApiError, authenticatedGet, signedPost } from '../api'
import { useAuth } from '../auth-context'
import { formatNumber, formatTimestamp } from '../format'
import type { FeedSources, OperatorSession, PriceSource, PriceSourcesState, SourceObservation } from '../types'

function fetchPriceSources(session: OperatorSession) {
  return authenticatedGet<PriceSourcesState>(session, '/operators/price-sources')
}

function formatPrice(observation: SourceObservation) {
  const value = observation.price / 10 ** observation.decimals
  return new Intl.NumberFormat('en-US', { maximumFractionDigits: Math.min(observation.decimals, 8) }).format(value)
}

// Freezing the last source still polled leaves the feed without a price of this node's own.
function freezeWarning(feed: FeedSources, source: PriceSource, isCoordinator: boolean) {
  const othersActive = feed.sources.some((other) => other.name !== source.name && other.state === 'active')
  const lines = [
    `Freeze ${source.name} for ${feed.symbol}?`,
    'This node stops polling it and keeps it frozen across restarts. Other nodes are not affected.',
  ]
  if (!othersActive) {
    lines.push(`It is the last active source of ${feed.symbol}: this node will stop attesting the feed, and every cross pair priced from it, and will refuse to sign rates for them.`)
    if (isCoordinator) {
      lines.push('This node is the coordinator, so priced issuance at these feeds stops for the whole network until a source is unfrozen.')
    }
  }
  return lines.join('\n\n')
}

export function PriceSourcesPage() {
  const { session, logout } = useAuth()
  const [state, setState] = useState<PriceSourcesState | null>(null)
  const [loading, setLoading] = useState(true)
  const [busyKey, setBusyKey] = useState<string | null>(null)
  const [error, setError] = useState('')

  function fail(cause: unknown, fallback: string) {
    if (cause instanceof ApiError && cause.status === 401) logout()
    else setError(cause instanceof Error ? cause.message : fallback)
  }

  async function load() {
    if (!session) return
    setLoading(true)
    setError('')
    try { setState(await fetchPriceSources(session)) }
    catch (cause) { fail(cause, 'Could not load price sources.') }
    finally { setLoading(false) }
  }

  useEffect(() => {
    if (!session) return
    let active = true
    fetchPriceSources(session)
      .then((next) => { if (active) setState(next) })
      .catch((cause: unknown) => {
        if (!active) return
        if (cause instanceof ApiError && cause.status === 401) logout()
        else setError(cause instanceof Error ? cause.message : 'Could not load price sources.')
      })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [session, logout])

  async function setFrozen(feed: FeedSources, source: PriceSource, frozen: boolean) {
    if (!session || !state) return
    if (frozen && !window.confirm(freezeWarning(feed, source, state.is_coordinator))) return
    setBusyKey(`${feed.id}:${source.name}`)
    setError('')
    try {
      const path = frozen ? '/operators/price-sources/freeze' : '/operators/price-sources/unfreeze'
      setState(await signedPost<PriceSourcesState>(session, path, { feed_id: feed.id, source: source.name }))
    } catch (cause) { fail(cause, frozen ? 'Could not freeze the source.' : 'Could not unfreeze the source.') }
    finally { setBusyKey(null) }
  }

  const feeds = state?.feeds ?? []
  const sources = feeds.flatMap((feed) => feed.sources)
  const count = (value: PriceSource['state']) => sources.filter((source) => source.state === value).length
  const unpriced = feeds.filter((feed) => feed.sources.length === 0)

  return <div className="page price-sources-page">
    <header className="page-header"><div><span className="eyebrow">Price feeds</span><h1>Price sources</h1>
      <p>The sources this node polls for each direct feed. Freezing a source affects only this node.</p></div>
      <button className="secondary-button icon-only-mobile" type="button" onClick={() => void load()} disabled={loading}>
        <RefreshCw size={16} className={loading ? 'spin' : ''} /><span>Refresh</span>
      </button>
    </header>
    {error && <div className="page-error" role="alert">{error}</div>}
    {state?.is_coordinator && <div className="page-note">This node is the coordinator. A feed it cannot price cannot be issued at by the network.</div>}

    <section className="storm-eye-summary" aria-label="Price source summary">
      <div><span>Feeds priced</span><strong>{state ? feeds.filter((feed) => feed.available).length : '—'}</strong><small>of {feeds.length} direct feeds</small></div>
      <div><span>Active</span><strong>{state ? count('active') : '—'}</strong><small>polled every cycle</small></div>
      <div><span>Dropped</span><strong>{state ? count('dropped') : '—'}</strong><small>retried after a pause</small></div>
      <div><span>Frozen</span><strong>{state ? count('frozen') : '—'}</strong><small>held by the operator</small></div>
    </section>

    <section className="storm-eye-inventory">
      <div className="table-wrap storm-eye-table-wrap">
        <table className="price-source-table">
          <thead><tr><th>Feed</th><th>Source</th><th>State</th><th>Last price</th><th>Observed</th><th>Failures</th><th>Action</th></tr></thead>
          <tbody>
            {feeds.flatMap((feed) => feed.sources.map((source) => {
              const key = `${feed.id}:${source.name}`
              const busy = busyKey === key
              return <tr key={key}>
                <td data-label="Feed"><strong>{feed.symbol}</strong><small>Feed {feed.id} · <span className={`status-pill ${feed.available ? 'active' : 'unavailable'}`}>{feed.available ? 'priced' : 'unavailable'}</span></small></td>
                <td data-label="Source">{source.name}</td>
                <td data-label="State"><span className={`status-pill ${source.state}`}>{source.state}</span>
                  {source.state === 'frozen' && <small>since {formatTimestamp(source.frozen_at)}</small>}
                  {source.state === 'dropped' && <small>retry {formatTimestamp(source.retry_at)}</small>}</td>
                <td className="price-cell" data-label="Last price">{source.observation ? formatPrice(source.observation) : <span className="muted-cell">—</span>}</td>
                <td data-label="Observed">{source.observation ? formatTimestamp(source.observation.observed_at) : <span className="muted-cell">—</span>}
                  {source.observation && <small>valid until {formatTimestamp(source.observation.valid_until)}</small>}</td>
                <td className="muted-cell" data-label="Failures">{formatNumber(source.failures)}</td>
                <td data-label="Action">{source.state === 'frozen'
                  ? <button className="secondary-button" type="button" disabled={busy} onClick={() => void setFrozen(feed, source, false)}><Play size={15} /> {busy ? 'Unfreezing…' : 'Unfreeze'}</button>
                  : <button className="secondary-button" type="button" disabled={busy} onClick={() => void setFrozen(feed, source, true)}><Snowflake size={15} /> {busy ? 'Freezing…' : 'Freeze'}</button>}</td>
              </tr>
            }))}
            {unpriced.map((feed) => <tr key={`${feed.id}:none`}>
              <td data-label="Feed"><strong>{feed.symbol}</strong><small>Feed {feed.id} · <span className="status-pill unavailable">unavailable</span></small></td>
              <td className="muted-cell" data-label="Source" colSpan={6}>No source is configured for this feed on this node.</td>
            </tr>)}
            {!loading && feeds.length === 0 && <tr><td className="empty-row" colSpan={7}>No direct feeds are registered.</td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  </div>
}
