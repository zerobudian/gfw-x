import { useState, type ReactNode } from 'react'
import { readSafeState, markVerified } from './safeState'
import { SafeVerification } from './SafeVerification'

/**
 * SafeGate is the browser-side verification gate placed BEFORE the GFW X
 * administrative UI (and therefore before auth / first-run setup).
 *
 *   Access → Safe Verified? → (no / expired) Safe Verification → Auth/FirstRun → Dashboard
 *
 * Once verified, the result is cached in sessionStorage for SAFE_TTL minutes,
 * so page refreshes and in-dashboard navigation do not re-challenge. When the
 * window expires (or a fresh tab opens), the gate re-verifies before the UI is
 * mounted. The GFW X <App/> is intentionally not mounted while unverified.
 *
 * Security note: this is an additional browser-side risk/challenge layer only.
 * Backend authentication and authorization remain the authoritative boundary.
 * A pure client-side gate can be bypassed and must not be described otherwise.
 */
export function SafeGate({ children }: { children: ReactNode }) {
  const [done, setDone] = useState(() => readSafeState() !== null)

  if (!done) {
    return (
      <SafeVerification
        onVerified={() => {
          markVerified()
          setDone(true)
        }}
      />
    )
  }

  return <>{children}</>
}