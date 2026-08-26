import { Clock3, KeyRound, LogOut, Radio, ShieldCheck } from 'lucide-react'
import { useAuth } from '../auth-context'
import { shortKey } from '../format'

export function SettingsPage() {
  const { session, logout } = useAuth()
  if (!session) return null
  return (
    <div className="page narrow-page">
      <header className="page-header"><div><span className="eyebrow">Operator profile</span><h1>Settings</h1>
        <p>Current browser session and node connection.</p></div></header>
      <section className="settings-section">
        <div className="section-heading"><div><span className="eyebrow">Identity</span><h2>Active operator</h2></div>
          <span className="status-pill active"><ShieldCheck size={13} /> Authenticated</span></div>
        <dl className="settings-list">
          <div><dt><KeyRound size={16} /> Public key</dt><dd><code title={session.identity.publicKey}>{shortKey(session.identity.publicKey, 13)}</code></dd></div>
          <div><dt><Radio size={16} /> Authentication address</dt><dd><code>{session.identity.address}</code></dd></div>
          <div><dt><Clock3 size={16} /> Session expires</dt><dd>{new Date(session.expiresAt * 1000).toLocaleString()}</dd></div>
        </dl>
      </section>
      <section className="settings-section danger-section">
        <div><span className="eyebrow">Session control</span><h2>End operator session</h2>
          <p>Clears in-memory key material and this tab's saved bearer session.</p></div>
        <button className="danger-button" type="button" onClick={logout}><LogOut size={17} /> Log out</button>
      </section>
    </div>
  )
}