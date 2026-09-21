/**
 * GFW X Safe Gate — verification state ledger.
 *
 * Safe is an additional browser-side verification layer in front of the
 * GFW X administrative UI. It is NOT a substitute for backend authentication:
 * backend auth (Argon2id session, CSRF, origin protection, rate limit) remains
 * the security boundary. This module only tracks when the front-end gate may
 * be skipped.
 *
 * State is kept in sessionStorage with an explicit short TTL so that a page
 * refresh or in-dashboard route switch within the window does not re-challenge,
 * while a fresh navigation (or an expired session) re-verifies.
 */

export const SAFE_TTL = 5 * 60 * 1000 // 5 minutes, verified then valid for N ms

const KEY = 'gfwx.safe.gate'

export interface SafeState {
  verified: boolean
  verifiedAt: number
  expiresAt: number
}

/**
 * Return the current gate state if still valid, otherwise null.
 * Returns null for any expired / malformed / disabled entry.
 */
export function readSafeState(): SafeState | null {
  try {
    const raw = sessionStorage.getItem(KEY)
    if (!raw) return null
    const st = JSON.parse(raw) as SafeState
    if (!st || st.verified !== true) return null
    if (!Number.isFinite(st.expiresAt) || !Number.isFinite(st.verifiedAt)) {
      sessionStorage.removeItem(KEY)
      return null
    }
    if (Date.now() >= st.expiresAt) {
      sessionStorage.removeItem(KEY)
      return null
    }
    return st
  } catch {
    return null
  }
}

/** Record a fresh verification with a new TTL window. */
export function markVerified(): SafeState {
  const verifiedAt = Date.now()
  const st: SafeState = { verified: true, verifiedAt, expiresAt: verifiedAt + SAFE_TTL }
  try {
    sessionStorage.setItem(KEY, JSON.stringify(st))
  } catch {
    // private browsing / storage disabled: fall back to in-memory only
    // (the gate will re-run on next mount, which is the safe default).
  }
  return st
}