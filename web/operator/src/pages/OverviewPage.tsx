import { useEffect, useState } from 'react'
import { Activity, Ban, Check, CircleDot, Clock3, Copy, RefreshCw, Server, ShieldCheck, Vote } from 'lucide-react'
import { ApiError, authenticatedGet } from '../api'
import { useAuth } from '../auth-context'
import { formatNumber, formatTimestamp, shortKey } from '../format'
import type { NetworkPeer, NetworkState, OperatorSession } from '../types'

function fetchOverview(session: OperatorSession) {
  return Promise.all([
    authenticatedGet<NetworkState>(session, '/operators/state'),
    authenticatedGet<NetworkPeer[]>(session, '/operators/state/peers'),
  ])
}

export function OverviewPage() {
  const { session, logout } = useAuth()
  const [network, setNetwork] = useState<NetworkState | null>(null)
  const [peers, setPeers] = useState<NetworkPeer[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [copied, setCopied] = useState('')

  async function load() {
    if (!session) return
    setLoading(true); setError('')
    try {
      const [nextNetwork, nextPeers] = await fetchOverview(session)
      setNetwork(nextNetwork); setPeers(nextPeers)
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 401) logout()
      else setError(cause instanceof Error ? cause.message : 'Could not load network state.')
    } finally { setLoading(false) }
  }

  useEffect(() => {
    if (!session) return
    let active = true
    fetchOverview(session)
      .then(([nextNetwork, nextPeers]) => {
        if (!active) return
        setNetwork(nextNetwork); setPeers(nextPeers)
      })
      .catch((cause: unknown) => {
        if (!active) return
        if (cause instanceof ApiError && cause.status === 401) logout()
        else setError(cause instanceof Error ? cause.message : 'Could not load network state.')
      })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [session, logout])

  async function copyKey(key: string) {
    await navigator.clipboard.writeText(key); setCopied(key)
    window.setTimeout(() => setCopied(''), 1200)
  }

  const onlinePercent = network?.total_peers
    ? Math.round((network.online_peers / network.total_peers) * 100) : 0

  return (
    <div className="page">
      <header className="page-header">
        <div><span className="eyebrow">Live network</span><h1>Overview</h1>
          <p>Node membership, connectivity and governance at a glance.</p></div>
        <button className="secondary-button" type="button" onClick={() => void load()} disabled={loading}>
          <RefreshCw size={16} className={loading ? 'spin' : ''} /> Refresh
        </button>
      </header>
      {error && <div className="page-error" role="alert">{error}</div>}
      <section className="health-strip" aria-label="Network health">
        <div><span className="pulse-dot" /><span className="health-label">Network availability</span>
          <strong>{loading && !network ? '—' : `${onlinePercent}%`}</strong></div>
        <div className="health-track" aria-hidden="true"><span style={{ width: `${onlinePercent}%` }} /></div>
        <span>{network?.online_peers ?? 0} of {network?.total_peers ?? 0} nodes online</span>
      </section>
      <section className="metric-grid">
        <article className="metric"><span><Server size={17} /> Block height</span>
          <strong>{network ? formatNumber(network.block_height) : '—'}</strong><small>Current protocol height</small></article>
        <article className="metric"><span><Activity size={17} /> Active nodes</span>
          <strong>{network?.online_peers ?? '—'}<em>/{network?.total_peers ?? '—'}</em></strong><small>{network?.inactive_peers ?? 0} inactive</small></article>
        <article className="metric"><span><Vote size={17} /> Open votings</span>
          <strong>{network?.pending_votings ?? '—'}</strong><small>{network?.approved_votings ?? 0} approved</small></article>
        <article className="metric"><span><ShieldCheck size={17} /> Local role</span>
          <strong className="metric-role">{network?.is_coordinator ? 'Coordinator' : 'Member'}</strong>
          <small>{network ? shortKey(network.local_public_key, 6) : '—'}</small></article>
      </section>
      <section className="data-section">
        <div className="section-heading"><div><span className="eyebrow">Runtime peer table</span><h2>Network members</h2></div>
          <div className="legend"><span><i className="status-dot active" /> Online</span>
            <span><i className="status-dot inactive" /> Inactive</span><span><i className="status-dot banned" /> Banned</span></div></div>
        <div className="table-wrap"><table><thead><tr><th>Member</th><th>Status</th><th>Endpoint</th><th>Last seen</th><th><span className="sr-only">Actions</span></th></tr></thead>
          <tbody>{peers.map((peer, index) => <tr key={peer.public_key}>
            <td><div className="member-cell"><span className="member-index">{String(index + 1).padStart(2, '0')}</span><div>
              <code title={peer.public_key}>{shortKey(peer.public_key)}</code><span className="member-badges">
                {peer.is_local && <b>LOCAL</b>}{peer.is_coordinator && <b>COORDINATOR</b>}</span></div></div></td>
            <td><span className={`status-pill ${peer.status}`}>{peer.status === 'banned' ? <Ban size={13} /> : <CircleDot size={13} />}
              {peer.status === 'controlled' ? 'online' : peer.status}</span></td>
            <td><code>{peer.socket_address ?? 'Not advertised'}</code></td>
            <td><span className="muted-cell"><Clock3 size={14} /> {formatTimestamp(peer.last_seen)}</span></td>
            <td><button className="icon-button" type="button" title="Copy public key" onClick={() => void copyKey(peer.public_key)}>
              {copied === peer.public_key ? <Check size={16} /> : <Copy size={16} />}</button></td>
          </tr>)}
          {!loading && peers.length === 0 && <tr><td colSpan={5} className="empty-row">No peers are registered.</td></tr>}</tbody></table></div>
      </section>
    </div>
  )
}