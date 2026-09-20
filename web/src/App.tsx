import { useEffect, useState, useSyncExternalStore, createContext, useContext } from 'react'
import { api } from './api'
import { messages, THEME_KEY, LANG_KEY, effectiveLang, detectTheme, detectLang, type Lang, type Theme } from './i18n'
import { DashboardPage } from './pages/Dashboard'
import { TrafficPage } from './pages/Traffic'
import { RulesPage } from './pages/Rules'
import { DetectPage } from './pages/Detect'
import { LogsPage } from './pages/Logs'
import { AnalyticsPage } from './pages/Analytics'
import { DevicesPage } from './pages/Devices'
import { ImportPage } from './pages/ImportExport'
import { SettingsPage } from './pages/Settings'

function subscribe(cb: () => void) {
  window.addEventListener('hashchange', cb)
  return () => window.removeEventListener('hashchange', cb)
}

function applyTheme(t: Theme) {
  const themeEl = document.documentElement
  if (t === 'system') {
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const on = () => { themeEl.dataset.theme = mq.matches ? 'dark' : 'light' }
    on()
    mq.addEventListener('change', on)
    return () => mq.removeEventListener('change', on)
  }
  themeEl.dataset.theme = t
  return () => {}
}

export type UIState = {
  lang: Lang
  theme: Theme
  t: { zh: string; en: string; sys: 'zh-CN' | 'en' } | null
}

// ---- context ----
export const RCtx = createContext<{ k: (key: string) => string }>({ k: (x) => x })

export function useT() {
  return useContext(RCtx).k
}

// tiny hash router
export function useRoute(): [string, (r: string) => void] {
  const [route] = useSyncExternalStore(subscribe, () => {
    const h = window.location.hash.replace(/^#\/?/, '')
    return h || 'dashboard'
  })
  const nav = (r: string) => {
    window.location.hash = '/' + r
  }
  return [route, nav]
}

const NAV: { key: string; route: string }[] = [
  { key: 'nav.dashboard', route: 'dashboard' },
  { key: 'nav.traffic', route: 'traffic' },
  { key: 'nav.rules', route: 'rules' },
  { key: 'nav.detect', route: 'detect' },
  { key: 'nav.logs', route: 'logs' },
  { key: 'nav.analytics', route: 'analytics' },
  { key: 'nav.devices', route: 'devices' },
  { key: 'nav.importexport', route: 'import' },
  { key: 'nav.settings', route: 'settings' },
]

export function App() {
  const [theme, setTheme] = useState<Theme>(() => detectTheme())
  const [lang, setLang] = useState<Lang>(() => detectLang())
  const [authed, setAuthed] = useState<null | boolean>(null)

  useEffect(() => {
    const cleanup = applyTheme(theme)
    document.documentElement.lang = effectiveLang(lang === 'system' ? null : lang)
    return cleanup
  }, [theme, lang])

  useEffect(() => {
    if (authed) return
    api.authStatus().then(() => setAuthed(true)).catch(() => setAuthed(false))
  }, [authed])

  const eff = effectiveLang(lang === 'system' ? null : lang)
  const dict = messages[eff] || messages.en
  const k = (key: string) => dict[key] || messages.en[key] || key

  if (authed === false) {
    return (
      <RCtx.Provider value={{ k }}>
        <Login k={k} onLogin={() => setAuthed(true)} />
      </RCtx.Provider>
    )
  }
  if (authed === null) {
    return (
      <RCtx.Provider value={{ k }}>
        <div className="login-wrap"><div className="login-card card">GFW X</div></div>
      </RCtx.Provider>
    )
  }

  // persist + push to server, keep local mirrors so Settings reflects server
  const setThemeBoth = (t: Theme) => { localStorage.setItem(THEME_KEY, t); setTheme(t); api.setTheme(t).catch(() => {}) }
  const setLangBoth = (l: Lang) => { localStorage.setItem(LANG_KEY, l); setLang(l); api.setLang(l).catch(() => {}) }

  return (
    <RCtx.Provider value={{ k }}>
      <Layout k={k} theme={theme} lang={lang} onTheme={setThemeBoth} onLang={setLangBoth} />
    </RCtx.Provider>
  )
}

function Login({ k, onLogin }: { k: (s: string) => string; onLogin: () => void }) {
  const [u, setU] = useState('')
  const [p, setP] = useState('')
  const [err, setErr] = useState('')
  const submit = async () => {
    if (!u || !p) { setErr(k('label.invalid')); return }
    try {
      await api.login(u, p)
      onLogin()
    } catch (e: any) {
      setErr(e.message || k('msg.error'))
    }
  }
  return (
    <div className="login-wrap">
      <div className="login-card card">
        <div style={{ textAlign: 'center', marginBottom: 16 }}>
          <div className="brand-mark" style={{ display: 'inline-grid', marginBottom: 8 }}>GX</div>
          <div style={{ fontWeight: 700, letterSpacing: -0.3 }}>{k('app.name')}</div>
          <div className="small muted">{k('app.tagline')}</div>
        </div>
        <div className="field">
          <label>{k('label.username')}</label>
          <input value={u} onChange={(e) => setU(e.target.value)} autoFocus />
        </div>
        <div className="field">
          <label>{k('label.password')}</label>
          <input type="password" value={p} onChange={(e) => setP(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && submit()} />
        </div>
        {err && <div className="small" style={{ color: 'var(--bad)', marginBottom: 10 }}>{err}</div>}
        <button className="btn primary" style={{ width: '100%' }} onClick={submit}>{k('label.login')}</button>
      </div>
    </div>
  )
}

function Layout({ k, theme, lang, onTheme, onLang }: { k: (s: string) => string; theme: Theme; lang: Lang; onTheme: (t: Theme) => void; onLang: (l: Lang) => void }) {
  const [route, nav] = useRoute()
  const [status, setStatus] = useState<any>(null)

  useEffect(() => {
    let alive = true
    const tick = async () => {
      try { const st = await api.status(); if (alive) setStatus(st) } catch { /* server restart */ }
    }
    tick()
    const id = window.setInterval(tick, 2000)
    return () => { alive = false; window.clearInterval(id) }
  }, [])

  const mode = status?.mode || 'block'

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">GX</div>
          <div>
            <div className="brand-name">{k('app.name')}</div>
            <div className="brand-tag">{k('app.tagline')}</div>
          </div>
        </div>
        <nav className="nav">
          {NAV.map((n) => (
            <button key={n.route} className={'nav-item' + (route === n.route ? ' active' : '')} onClick={() => nav(n.route)}>
              {k(n.key)}
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">{k('label.version')} · GFW X</div>
      </aside>
      <main className="main">
        <div className="topbar">
          <div className="page-title">{k(titleKey(route))}</div>
          <div className="row">
            <ModeSwitch k={k} current={mode} nav={nav} />
          </div>
        </div>
        {route === 'dashboard' && <DashboardPage k={k} status={status} />}
        {route === 'traffic' && <TrafficPage k={k} />}
        {route === 'rules' && <RulesPage k={k} />}
        {route === 'detect' && <DetectPage k={k} />}
        {route === 'logs' && <LogsPage k={k} />}
        {route === 'analytics' && <AnalyticsPage k={k} />}
        {route === 'devices' && <DevicesPage k={k} />}
        {route === 'import' && <ImportPage k={k} />}
        {route === 'settings' && <SettingsPage k={k} theme={theme} lang={lang} onTheme={onTheme} onLang={onLang} />}
      </main>
    </div>
  )
}

function titleKey(route: string): string {
  const m: Record<string, string> = {
    dashboard: 'nav.dashboard', traffic: 'nav.traffic', rules: 'nav.rules', detect: 'nav.detect',
    logs: 'nav.logs', analytics: 'nav.analytics', devices: 'nav.devices', import: 'nav.importexport', settings: 'nav.settings',
  }
  return m[route] || 'nav.dashboard'
}

function ModeSwitch({ k, current, nav }: { k: (s: string) => string; current: string; nav: (r: string) => void }) {
  const modes = ['bypass', 'block', 'custom']
  const switchMode = async (m: string) => {
    try { await api.mode(m) } catch { /* ignore */ }
  }
  void nav
  return (
    <div className="mode-switch">
      {modes.map((m) => (
        <button key={m} className={'mode-btn' + (current === m ? ' active' : '')} onClick={() => switchMode(m)}>
          {k('mode.' + m)}
        </button>
      ))}
    </div>
  )
}
