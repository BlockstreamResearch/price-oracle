import { Activity, LayoutDashboard, LogOut, Settings, Vote } from 'lucide-react'
import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../auth-context'
import { shortKey } from '../format'

const navigation = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/votings', label: 'Votings', icon: Vote, end: false },
  { to: '/settings', label: 'Settings', icon: Settings, end: false },
]

export function AppShell() {
  const { session, logout } = useAuth()
  if (!session) return null

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup">
          <span className="brand-mark" aria-hidden="true"><i /><i /><i /></span>
          <span><strong>STORM</strong><small>Operator console</small></span>
        </div>

        <nav className="primary-nav" aria-label="Primary navigation">
          <span className="nav-label">Workspace</span>
          {navigation.map(({ to, label, icon: Icon, end }) => (
            <NavLink key={to} to={to} end={end}>
              <Icon size={18} strokeWidth={1.8} /><span>{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-session">
          <div className="session-signal"><Activity size={16} /><span>Authenticated</span></div>
          <code title={session.identity.publicKey}>{shortKey(session.identity.publicKey, 7)}</code>
          <button type="button" className="sidebar-logout" onClick={logout}>
            <LogOut size={16} /> Log out
          </button>
        </div>
      </aside>

      <main className="workspace"><Outlet /></main>

      <nav className="mobile-nav" aria-label="Mobile navigation">
        {navigation.map(({ to, label, icon: Icon, end }) => (
          <NavLink key={to} to={to} end={end}>
            <Icon size={19} /><span>{label}</span>
          </NavLink>
        ))}
      </nav>
    </div>
  )
}