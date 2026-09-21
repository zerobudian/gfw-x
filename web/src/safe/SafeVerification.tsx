import { useEffect, useRef } from 'react'

/**
 * Full-screen host for the original BudianCloud Safe verification engine.
 *
 * The vanilla JS engine (app.gate.js + behavior-model.js + challenge-worker.js)
 * is served from /safe/* and drives the DOM skeleton injected below — keeping
 * the upstream behaviour-analysis, fingerprinting, FP4 risk model, click/image
 * challenge state machine, proof-of-work and ban logic fully intact.
 *
 * On completion the engine calls window.__SAFE_ON_COMPLETE__ instead of
 * navigating; we then fade the host out and signal our parent.
 */

declare global {
  interface Window {
    __SAFE_ON_COMPLETE__?: () => void
    __SAFE_ASSET_PATH__?: { worker: string }
  }
}

const WORKER_URL = '/safe/challenge-worker.js'

const SAFE_MARKUP = `
<header class="site-header">
  <div class="brand"><svg viewBox="0 0 28 24" aria-hidden="true"><path d="M8 19h13a5 5 0 0 0 .6-10A8 8 0 0 0 6.1 8.2 5.5 5.5 0 0 0 8 19Z" fill="currentColor"/></svg><span>BudianCloud</span></div>
  <button class="language quiet-button" id="language" type="button" aria-label="切换为中文"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a18 18 0 0 1 0 18 18 18 0 0 1 0-18Z"/></svg><span id="language-label">中文</span></button>
</header>
<main>
  <section class="verification" aria-labelledby="heading">
    <div class="shield" aria-hidden="true"><svg viewBox="0 0 32 36"><path d="m16 3 11 4v10c0 8-11 15-11 15S5 25 5 17V7Z"/><path d="m11 17 3.5 3.5L22 13"/></svg></div>
    <h1 id="heading">Checking your browser</h1>
    <p class="intro" id="intro">Just a moment. You’ll continue automatically.</p>
    <div class="widget" id="widget" data-state="checking">
      <button class="widget-body" id="widget-button" type="button" disabled aria-describedby="status-detail">
        <span class="status-icon" id="status-icon" aria-hidden="true"><span class="spinner"></span><svg class="check" viewBox="0 0 24 24"><path d="m5 12 4.5 4.5L19 7"/></svg><svg class="question" viewBox="0 0 24 24"><path d="M9 8a3 3 0 1 1 4.8 2.4c-1.2.7-1.8 1.1-1.8 2.6M12 17h.01"/></svg><svg class="error-icon" viewBox="0 0 24 24"><path d="M12 6v7m0 4h.01"/></svg></span>
        <span class="widget-copy" role="status" aria-live="polite" aria-atomic="true"><strong id="status">Verifying…</strong><span id="status-detail">Checking your browser</span></span>
        <span class="widget-brand" aria-hidden="true"><svg viewBox="0 0 28 24"><path d="M8 19h13a5 5 0 0 0 .6-10A8 8 0 0 0 6.1 8.2 5.5 5.5 0 0 0 8 19Z" fill="currentColor"/></svg><span>BUDIAN</span><small>VERIFY</small></span>
      </button>
      <div class="progress-track" aria-hidden="true"><span id="progress"></span></div>
    </div>
    <ol class="steps" aria-label="Verification progress" id="steps">
      <li data-step="0" class="active"><span class="step-mark"></span><span data-i18n="stepBrowser">Browser</span></li>
      <li data-step="1"><span class="step-mark"></span><span data-i18n="stepCheck">Verification</span></li>
      <li data-step="2"><span class="step-mark"></span><span data-i18n="stepDone">Continue</span></li>
    </ol>
    <div class="destination"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="10" width="14" height="11" rx="3"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg><span>GFW&nbsp;X</span><svg class="destination-arrow" viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14m-5-5 5 5-5 5"/></svg></div>
    <div class="actions">
      <button class="text-button" id="image-option" type="button" data-i18n="useImages">Use an image challenge</button>
      <button class="text-button" id="retry" type="button" hidden data-i18n="retry">Try again</button>
      <a class="continue-link" id="continue" hidden href="#safe-continue" data-i18n="continueNow">Continue now</a>
    </div>
    <div class="trap" aria-hidden="true" inert><label for="website">Leave this field empty</label><input id="website" type="text" name="website" tabindex="-1" autocomplete="off"></div>
    <noscript><p class="noscript">请启用 JavaScript 后重新加载此页面。<br>Enable JavaScript and reload to continue.</p></noscript>
  </section>
</main>
<footer class="site-footer">
  <span class="footer-note"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m12 3 7 3v6c0 5-7 9-7 9s-7-4-7-9V6Z"/><path d="m9 12 2 2 4-4"/></svg><span data-i18n="footer">An extra moment. A safer visit.</span></span>
  <nav aria-label="Support"><button type="button" class="quiet-button" id="privacy" data-i18n="privacy">Privacy</button><span aria-hidden="true">·</span><button type="button" class="quiet-button" id="help" data-i18n="help">Help</button></nav>
</footer>
<dialog class="challenge-dialog" id="challenge-dialog" aria-labelledby="challenge-title" aria-describedby="challenge-instruction">
  <div class="challenge-header"><div><p id="challenge-instruction" data-i18n="selectAll">Select all images with</p><h2 id="challenge-title">traffic lights</h2><p class="challenge-hint" id="challenge-hint" data-i18n="selectHint">Select every match, then verify.</p></div><button class="icon-button close-challenge" id="close-challenge" type="button" aria-label="Close"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div>
  <div class="image-grid" id="image-grid" role="group" aria-labelledby="challenge-title"></div>
  <div class="text-challenge" id="text-challenge" hidden><label id="math-label" for="math-answer"></label><input id="math-answer" type="text" inputmode="numeric" autocomplete="off" maxlength="3" aria-describedby="challenge-error"></div>
  <p class="challenge-error" id="challenge-error" role="status" aria-live="polite"></p>
  <div class="challenge-controls"><button class="icon-button" id="refresh-challenge" type="button" aria-label="New challenge"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 7v5h-5M4 17v-5h5"/><path d="M6.1 6.1A8 8 0 0 1 20 12M4 12a8 8 0 0 0 13.9 5.9"/></svg></button><button class="challenge-alternative text-button" id="alternative" type="button" data-i18n="textAlternative">Use a text question</button><button class="verify-selection" id="verify-selection" type="button" data-i18n="verify">Verify</button></div>
  <div class="challenge-attribution">BudianCloud Verify</div>
</dialog>
<dialog class="info-dialog" id="info-dialog" aria-labelledby="info-title"><div class="info-heading"><h2 id="info-title"></h2><button class="icon-button" id="close-info" type="button" aria-label="Close"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div><p id="info-copy"></p><button class="info-done" id="info-done" type="button" data-i18n="gotIt">Got it</button></dialog>
`

export function SafeVerification({ onVerified }: { onVerified: () => void }) {
  const hostRef = useRef<HTMLDivElement>(null)
  const doneRef = useRef(false)

  useEffect(() => {
    if (doneRef.current || !hostRef.current) return
    doneRef.current = true

    const host = hostRef.current
    host.innerHTML = SAFE_MARKUP

    // Wire the upstream completion signal to a fade-out then the real callback.
    window.__SAFE_ON_COMPLETE__ = () => {
      const el = hostRef.current
      if (el) {
        el.style.transition = 'opacity 0.25s ease'
        el.style.opacity = '0'
      }
      window.setTimeout(() => onVerified(), 260)
    }
    window.__SAFE_ASSET_PATH__ = { worker: WORKER_URL }

    // Styles + model + engine, in that order (model must exist before engine runs).
    const styleLink = document.createElement('link')
    styleLink.rel = 'stylesheet'
    styleLink.href = '/safe/styles.css'

    const modelScript = document.createElement('script')
    modelScript.src = '/safe/behavior-model.js'

    const engineScript = document.createElement('script')
    engineScript.src = '/safe/app.gate.js'

    const mount = () => {
      host.appendChild(styleLink)
      host.appendChild(modelScript)
      host.appendChild(engineScript)
    }
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', mount, { once: true })
    } else {
      mount()
    }

    return () => {
      const cleanup = () => (window.__SAFE_ON_COMPLETE__ = undefined)
      window.setTimeout(cleanup, 0)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div
      ref={hostRef}
      className="gfwx-safegate-host"
      style={{ minHeight: '100svh', background: 'transparent' }}
    />
  )
}