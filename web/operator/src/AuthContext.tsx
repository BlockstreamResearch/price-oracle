import {
  useCallback,
  useEffect,
  useState,
  type ReactNode,
} from 'react'
import { authenticateOperator } from './api'
import { AuthContext } from './auth-context'
import { createOperatorIdentity } from './crypto'
import type { AuthNetwork, OperatorSession } from './types'

const SESSION_KEY = 'storm-operator-session'

type StoredSession = {
  token: string
  expiresAt: number
  publicKey: string
  address: string
  network: AuthNetwork
  secretKey: string
}

function restoreSession(): OperatorSession | null {
  try {
    const stored = JSON.parse(sessionStorage.getItem(SESSION_KEY) ?? 'null') as StoredSession | null
    if (!stored || stored.expiresAt <= Math.floor(Date.now() / 1000) ||
      typeof stored.token !== 'string' || !/^[0-9a-f]{64}$/i.test(stored.publicKey) ||
      typeof stored.address !== 'string' || typeof stored.network !== 'string' ||
      !/^[0-9a-f]{64}$/i.test(stored.secretKey)) {
      sessionStorage.removeItem(SESSION_KEY)
      return null
    }
    const identity = createOperatorIdentity(stored.secretKey, stored.network)
    if (identity.publicKey !== stored.publicKey || identity.address !== stored.address ||
      identity.network !== stored.network) {
      identity.destroy()
      sessionStorage.removeItem(SESSION_KEY)
      return null
    }
    return {
      token: stored.token,
      expiresAt: stored.expiresAt,
      identity,
    }
  } catch {
    sessionStorage.removeItem(SESSION_KEY)
    return null
  }
}

function storeSession(session: OperatorSession, secretKey: string) {
  const { address, network } = session.identity
  if (!address || !network) {
    throw new Error('The operator identity is missing its Elements network.')
  }

  sessionStorage.setItem(SESSION_KEY, JSON.stringify({
    token: session.token,
    expiresAt: session.expiresAt,
    publicKey: session.identity.publicKey,
    address,
    network,
    secretKey: secretKey.trim().replace(/^0x/i, '').toLowerCase(),
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
      storeSession(nextSession, secretKey)
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