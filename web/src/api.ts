const base = '/api'
let csrfToken = ''

async function req<T>(method: string, path: string, body?: unknown, opts: { form?: boolean } = {}): Promise<T> {
  const headers: Record<string, string> = {}
  let payload: BodyInit | undefined
  if (body !== undefined) {
    if (opts.form) {
      payload = body as BodyInit
    } else {
      headers['Content-Type'] = 'application/json'
      payload = JSON.stringify(body)
    }
  }
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && path !== '/login') {
    if (!csrfToken) {
      const status = await req<AuthStatus>('GET', '/auth/status')
      csrfToken = status.csrf
    }
    headers['X-CSRF-Token'] = csrfToken
  }
  const res = await fetch(base + path, { method, headers, body: payload })
  const ct = res.headers.get('content-type') || ''
  const text = await res.text()
  let data: any = {}
  if (text) {
    try {
      data = ct.includes('application/json') || text.trim().startsWith('{') || text.trim().startsWith('[') ? JSON.parse(text) : { raw: text }
    } catch {
      data = { raw: text }
    }
  }
  if (!res.ok) {
    throw new Error(data.error || data.raw || `HTTP ${res.status}`)
  }
  if (path === '/login' || path === '/auth/status') {
    csrfToken = (data as LoginResult | AuthStatus).csrf || ''
  }
  return data as T
}

// ---- Types (mirror Go JSON shapes) ----

export interface Snapshot {
  flows_seen: number
  packets: number
  decisions: number
  allowed: number
  blocked: number
  unknown: number
  observed: number
  rate_limited: number
  rejected: number
  dropped: number
  bytes_up: number
  bytes_down: number
  blocked_today: number
}

export interface Status {
  mode: string
  mode_valid: string[]
  uptime_sec: number
  throughput_bps: number
  counters: Snapshot
  active_flows: number
  lookup_hits: number
  lookup_misses: number
  classifies: { [k: string]: number }
  slow_path: number
  cpu_cores: number
  memory_mb: number
  version: string
  detections: number
  theme: string
  lang: string
  log_degraded: string
}

export interface Event {
  id: number
  time: string
  src: string
  dst: string
  proto: string
  domain?: string
  sni?: string
  action: string
  matched_rule?: string
  category?: string
  confidence?: number
  bytes_up: number
  bytes_down: number
  duration_sec: number
}

export interface Rank {
  key: string
  count: number
}

export interface Matcher {
  field: string
  value: string
}

export interface Rule {
  id: string
  name: string
  kind: 'allow' | 'block' | 'observe' | 'ratelimit'
  enabled: boolean
  category: string
  matchers: Matcher[]
  hits: number
  last_hit: string
  source: string
  comment?: string
}

export interface Conflict {
  a: Rule
  b: Rule
  field: string
  value: string
}

export interface DetectInfo {
  enabled: boolean
  threshold: number
  auto_apply: boolean
  detections: number
}

export interface LoginResult {
  ok: string
  csrf: string
}

export interface AuthStatus {
  enabled: boolean
  csrf: string
  version: string
}

// ---- API ----

export const api = {
  status: () => req<Status>('GET', '/status'),
  events: (limit = 50) => req<Event[]>('GET', '/events?limit=' + limit),
  topDomains: (n = 20) => req<Rank[]>('GET', '/top/domains' + (n ? '?n=' + n : '')),
  topReasons: (n = 20) => req<Rank[]>('GET', '/top/reasons' + (n ? '?n=' + n : '')),
  protocols: () => req<Rank[]>('GET', '/protocols'),
  analytics: () => req<{ top_domains: Rank[]; top_reasons: Rank[]; protocols: Rank[] }>('GET', '/analytics'),
  mode: (m?: string) => (m ? req<{ mode: string }>('POST', '/mode', { mode: m }) : req<{ mode: string }>('GET', '/mode')),
  rules: () => req<Rule[]>('GET', '/rules'),
  addRule: (r: Rule) => req<Rule>('POST', '/rules', r),
  updateRule: (r: Rule) => req<Rule>('PUT', '/rules', r),
  deleteRule: (id: string) => req<{ deleted: string }>('DELETE', '/rules', { id }),
  ruleSearch: (q: string) => req<Rule[]>('GET', '/rules/search?q=' + encodeURIComponent(q)),
  conflicts: () => req<Conflict[]>('GET', '/rules/conflicts'),
  presets: () => req<Record<string, string>>('GET', '/rules/presets'),
  applyPreset: (preset: string) => req<{ preset: string; rules: number }>('POST', '/rules/presets', { preset }),
  importPreview: (content: string) => req<{ parsed: Rule[]; count: number; conflicts: Conflict[]; applied: boolean }>('POST', '/rules/import/preview', new URLSearchParams({ content }), { form: true }),
  importRules: (content: string, format?: string) => req<{ imported: number; applied: boolean }>('POST', '/rules/import', new URLSearchParams({ content, ...(format ? { format } : {}) }), { form: true }),
  config: () => req<any>('GET', '/config'),
  authStatus: () => req<AuthStatus>('GET', '/auth/status'),
  detect: () => req<DetectInfo>('GET', '/detect'),
  login: (username: string, password: string) => req<LoginResult>('POST', '/login', { username, password }),
  setTheme: (theme: string) => req<{ theme: string }>('POST', '/settings/theme', { theme }),
  setLang: (lang: string) => req<{ lang: string }>('POST', '/settings/lang', { lang }),
}

export const rawUrl = (path: string, params: Record<string, string> = {}) => {
  const q = new URLSearchParams(params).toString()
  return `${base}${path}${q ? '?' + q : ''}`
}

export function fmtBytes(b: number): string {
  if (!b || b <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  const i = Math.min(units.length - 1, Math.floor(Math.log(b) / Math.log(1024)))
  return (b / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + ' ' + units[i]
}

export function fmtRate(bps: number): string {
  if (!bps || bps <= 0) return '0 b/s'
  const units = ['b/s', 'Kb/s', 'Mb/s', 'Gb/s', 'Tb/s']
  const i = Math.min(units.length - 1, Math.floor(Math.log(bps) / Math.log(1000)))
  return (bps / Math.pow(1000, i)).toFixed(1) + ' ' + units[i]
}

export function fmtUptime(sec: number): string {
  if (sec < 0) sec = 0
  const d = Math.floor(sec / 86400)
  const h = Math.floor((sec % 86400) / 3600)
  const m = Math.floor((sec % 3600) / 60)
  const s = Math.floor(sec % 60)
  const parts: string[] = []
  if (d) parts.push(d + 'd')
  if (h) parts.push(h + 'h')
  if (m) parts.push(m + 'm')
  parts.push(s + 's')
  return parts.join(' ')
}

export function fmtTime(iso: string): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}
