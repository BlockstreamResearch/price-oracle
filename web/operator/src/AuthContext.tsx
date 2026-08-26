import {
  useCallback,
  useEffect,
  useState,
  type ReactNode,
} from 'react'
import { authenticateOperator } from './api'
import { AuthContext } from './auth-context'
import { createOperatorIdentity, createRestoredOperatorIdentity } from './crypto'
import type { OperatorSession } from './types'

const SESSION_KEY = 'storm-operator-session'

type StoredSession = {
  token: string
  expiresAt: number
  publicKey: string
  address: string
}

function restoreSession(): OperatorSession | null {
  try {
    const stored = JSON.parse(sessionStorage.getItem(SESSION_KEY) ?? 'null') as StoredSession | null
    if (!stored || stored.expiresAt <= Math.floor(Date.now() / 1000) ||
      typeof stored.token !== 'string' || !/^[0-9a-f]{66}$/i.test(stored.publicKey) ||
      typeof stored.address !== 'string') {
      sessionStorage.removeItem(SESSION_KEY)
      return null
    }
    return {
      token: stored.token,
      expiresAt: stored.expiresAt,
      identity: createRestoredOperatorIdentity(stored.publicKey, stored.address),
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
  } satisfies StoredSession))
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<OperatorSession | null>(restoreSession)

  const logout = useCallback(() => {
    sessionStorage.removeItem(SESSION_KEY)
    setSession((current) => {
      current?.identity.destroy()
      return null
    })
  }, [])

  const login = useCallback(async (secretKey: string) => {
    const identity = createOperatorIdentity(secretKey)
    try {
      const nextSession = await authenticateOperator(identity)
      storeSession(nextSession)
      setSession(nextSession)
    } catch (error) {
      identity.destroy()
      throw error
    }
  }, [])

  useEffect(() => {
    const clearIdentity = () => session?.identity.destroy()
    window.addEventListener('pagehide', clearIdentity)
    return () => window.removeEventListener('pagehide', clearIdentity)
  }, [session])

  return (
    <AuthContext.Provider value={{ session, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}