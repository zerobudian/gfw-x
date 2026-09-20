import type { ReactNode } from 'react'

export function Card({ title, children, className = '' }: { title?: string; children: ReactNode; className?: string }) {
  return (
    <div className={'card ' + className}>
      {title && <div className="card-title">{title}</div>}
      {children}
    </div>
  )
}

export function Stat({ value, label }: { value: ReactNode; label: string }) {
  return (
    <Card>
      <div className="stat">
        <div className="stat-value">{value}</div>
        <div className="stat-label">{label}</div>
      </div>
    </Card>
  )
}

export function Bar({ val, max }: { val: number; max: number }) {
  const pct = max > 0 ? Math.min(100, (val / max) * 100) : 0
  return <div className="bar-wrap"><div className="bar" style={{ width: pct + '%' }} /></div>
}

export function Doughnut({ data }: { data: { key: string; value: number; color: string }[] }) {
  const total = data.reduce((s, d) => s + d.value, 0) || 1
  let acc = 0
  const segs = data.map((d, i) => {
    const start = (acc / total) * 360
    acc += d.value
    const end = (acc / total) * 360
    return <Segment key={i} start={start} end={end} color={d.color} />
  })
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 18, flexWrap: 'wrap' }}>
      <svg viewBox="0 0 120 120" width="120" height="120" style={{ transform: 'rotate(-90deg)' }}>
        <circle cx="60" cy="60" r="48" fill="none" stroke="var(--bg-hover)" strokeWidth="14" />
        {segs}
      </svg>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {data.map((d) => (
          <div key={d.key} className="row small">
            <span className="dot" style={{ background: d.color }} />{d.key}
            <span className="muted">{d.value > 0 ? pct(d.key, data) : ''}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function pct(key: string, data: { key: string; value: number }[]) {
  const total = data.reduce((s, d) => s + d.value, 0) || 1
  const it = data.find((d) => d.key === key)!
  return ((it.value / total) * 100).toFixed(0) + '%'
}

function Segment({ start, end, color }: { start: number; end: number; color: string }) {
  const cx = 60, cy = 60, r = 48
  const large = end - start > 180 ? 1 : 0
  const a0 = ((start - 90) * Math.PI) / 180
  const a1 = ((end - 90) * Math.PI) / 180
  const x0 = cx + r * Math.cos(a0), y0 = cy + r * Math.sin(a0)
  const x1 = cx + r * Math.cos(a1), y1 = cy + r * Math.sin(a1)
  return <path d={`M ${x0} ${y0} A ${r} ${r} 0 ${large} 1 ${x1} ${y1}`} fill="none" stroke={color} strokeWidth="14" strokeLinecap="butt" />
}

export function Toasts({ items, dismiss }: { items: { id: number; msg: string }[]; dismiss: (id: number) => void }) {
  void dismiss
  return (
    <>
      {items.map((t) => (
        <div key={t.id} className="toast">{t.msg}</div>
      ))}
    </>
  )
}

export function actionBadge(action: string) {
  const cls = action === 'allow' ? 'allow' : action === 'block' ? 'block' : action === 'observe' ? 'observe' : action === 'ratelimit' ? 'ratelimit' : action === 'reject' ? 'reject' : 'drop'
  return <span className={'badge ' + cls}>{action}</span>
}

export function kindBadge(kind: string) {
  const cls = kind === 'allow' ? 'allow' : kind === 'block' ? 'block' : kind === 'observe' ? 'observe' : 'ratelimit'
  return <span className={'badge ' + cls}>{kind.toUpperCase()}</span>
}

export const PALETTE = ['#3d5afe', '#00b3a6', '#f5a623', '#e5484d', '#8b93a7', '#7c8cff', '#18a058', '#f2994a']