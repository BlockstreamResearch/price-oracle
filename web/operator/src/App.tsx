import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import './App.css'
import { AuthProvider } from './AuthContext'
import { useAuth } from './auth-context'
import { AppShell } from './components/AppShell'
import { LoginPage } from './pages/LoginPage'
import { OverviewPage } from './pages/OverviewPage'
import { SettingsPage } from './pages/SettingsPage'
import { VotingsPage } from './pages/VotingsPage'

function OperatorRoutes() {
  const { session } = useAuth()
  if (!session) return <LoginPage />

  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<OverviewPage />} />
        <Route path="votings" element={<VotingsPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <OperatorRoutes />
      </BrowserRouter>
    </AuthProvider>
  )
}