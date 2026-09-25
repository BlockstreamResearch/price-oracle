import {
  useCallback,
  useEffect,
  useState,
  type ReactNode,
} from 'react'
import { authenticateOperator, getAuthConfig } from './api'
import { AuthContext } from './auth-context'
import {
  connectHumid,
  restoreHumidIdentity,
  revokeHumidSession,
  subscribeToHumidChanges,
  validateHumidSession,
} from './humid'
import type { AuthNetwork, OperatorSession } from './types'

const SESSION_KEY = 'storm-operator-session'

type StoredSession = {
  token: string
  expiresAt: number
  publicKey: string
  address: string
  network: AuthNetwork
  chainId: string
  accountIdentifier: string
}

function restoreSession(): OperatorSession | null {
  try {
    const stored = JSON.parse(sessionStorage.getItem(SESSION_KEY) ?? 'null') as StoredSession | null
    if (!stored || stored.expiresAt <= Math.floor(Date.now() / 1000) ||
      typeof stored.token !== 'string' || !/^[0-9a-f]{66}$/i.test(stored.publicKey) ||
      typeof stored.address !== 'string' || typeof stored.network !== 'string' ||
      typeof stored.chainId !== 'string' || typeof stored.accountIdentifier !== 'string') {
      sessionStorage.removeItem(SESSION_KEY)
      return null
    }
    return {
      token: stored.token,
      expiresAt: stored.expiresAt,
      identity: restoreHumidIdentity(stored),
    }
  } catch {
    sessionStorage.removeItem(SESSION_KEY)
    return null
  }
}

function storeSession(session: OperatorSession) {
  sessionStorage.setItem(SESSION_KEY, JSON.stringify({
    token: session.token,
    expiresAt: session.expiresAt,
    publicKey: session.identity.publicKey,
    address: session.identity.address,
    network: session.identity.network,
    chainId: session.identity.chainId,
    accountIdentifier: session.identity.accountIdentifier,
  } satisfies StoredSession))
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<OperatorSession | null>(restoreSession)

  const clearSession = useCallback(() => {
    sessionStorage.removeItem(SESSION_KEY)
    setSession(null)
  }, [])

  const logout = useCallback(() => {
    clearSession()
    void revokeHumidSession()
  }, [clearSession])

  const login = useCallback(async () => {
    const config = await getAuthConfig()
    const identity = await connectHumid(config)
    const nextSession = await authenticateOperator(identity)
    storeSession(nextSession)
    setSession(nextSession)
  }, [])

  useEffect(() => {
    if (!session) return

    let cancelled = false
    void validateHumidSession(session.identity).then((valid) => {
      if (!valid && !cancelled) clearSession()
    })
    const unsubscribe = subscribeToHumidChanges(clearSession)

    return () => {
      cancelled = true
      unsubscribe()
    }
  }, [session, clearSession])

  useEffect(() => {
    if (!session) return
    const expiresIn = Math.max(0, session.expiresAt * 1000 - Date.now())
    const timeout = window.setTimeout(logout, expiresIn)
    return () => window.clearTimeout(timeout)
  }, [session, logout])

  return (
    <AuthContext.Provider value={{ session, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}