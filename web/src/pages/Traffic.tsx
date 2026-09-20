import { useEffect, useState } from 'react'
import { api, fmtBytes, fmtTime, type Rank, type Event, type Status } from '../api'
import { Card, Stat, Doughnut, PALETTE, actionBadge } from '../ui'

export function TrafficPage({ k }: { k: (s: string) => string }) {
  const [status, setStatus] = useState<Status | null>(null)
  const [events, setEvents] = useState<Event[]>([])
  const [protocols, setProtocols] = useState<Rank[]>([])

  useEffect(() => {
    let alive = true
    const tick = async () => {
      try {
        const [st, ev, pro] = await Promise.all([api.status(), api.events(100), api.protocols()])
        if (!alive) return
        setStatus(st); setEvents(ev); setProtocols(pro)
      } catch { }
    }
    tick()
    const id = window.setInterval(tick, 2500)
    return () => { alive = false; window.clearInterval(id) }
  }, [])

  const c = status?.counters
  const protoData = protocols.slice(0, 6).map((p, i) => ({ key: p.key, value: p.count, color: PALETTE[i % PALETTE.length] }))

  return (
    <>
      <div className="mini-stat-row">
        <Stat value={fmtBytes(c?.bytes_up || 0)} label="↑" />
        <Stat value={fmtBytes(c?.bytes_down || 0)} label="↓" />
        <Stat value={status?.active_flows || 0} label={k('label.activeFlows')} />
        <Stat value={status?.lookup_hits || 0} label="FastPath" />
        <Stat value={status?.lookup_misses || 0} label="SlowPath" />
        <Stat value={fmtBytes((c?.bytes_up || 0) + (c?.bytes_down || 0))} label="Σ" />
      </div>

      <div className="two-col" style={{ marginBottom: 16 }}>
        <Card title={k('label.actions') + ' / ' + k('label.decisions')}>
          <DecisionBars k={k} />
        </Card>
        <Card title={k('label.protocols')}>
          {protoData.length === 0 ? <div className="empty">{k('label.noEvents')}</div> : <Doughnut data={protoData} />}
        </Card>
      </div>

      <Card title={k('label.liveEvents')}>
        <div style={{ maxHeight: 520, overflow: 'auto' }}>
          <table>
            <thead>
              <tr>
                <th>{k('label.time')}</th><th>{k('label.source')}</th><th>{k('label.destination')}</th>
                <th>{k('label.protocol')}</th><th>{k('label.domain')}</th><th>{k('label.action')}</th>
                <th>↑/↓</th><th>{k('label.rule')}</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 && <tr><td colSpan={8} className="empty">{k('label.noEvents')}</td></tr>}
              {events.map((e) => (
                <tr key={e.id}>
                  <td className="mono">{fmtTime(e.time)}</td>
                  <td className="mono">{e.src}</td>
                  <td className="mono">{e.dst}</td>
                  <td>{e.proto}</td>
                  <td className="mono">{e.domain || e.sni || '—'}</td>
                  <td>{actionBadge(e.action)}</td>
                  <td className="mono small">{e.bytes_up ? fmtBytes(e.bytes_up) : ''}/{e.bytes_down ? fmtBytes(e.bytes_down) : ''}</td>
                  <td className="small muted">{e.matched_rule || ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  )
}

function DecisionBars({ k }: { k: (s: string) => string }) {
  const [status, setStatus] = useState<Status | null>(null)
  useEffect(() => {
    let alive = true
    const tick = () => api.status().then((st) => alive && setStatus(st)).catch(() => {})
    tick()
    const id = window.setInterval(tick, 2000)
    return () => { alive = false; window.clearInterval(id) }
  }, [])
  const c = status?.counters
  void k
  const rows = [
    ['allow', c?.allowed, 'var(--ok)'],
    ['block', c?.blocked, 'var(--bad)'],
    ['observe', c?.observed, 'var(--warn)'],
    ['ratelimit', c?.rate_limited, 'var(--warn)'],
    ['reject', c?.rejected, 'var(--bad)'],
    ['drop', c?.dropped, 'var(--unk)'],
  ] as [string, number | undefined, string][]
  const max = Math.max(1, ...rows.map((r) => r[1] || 0))
  return (
    <div className="row" style={{ flexDirection: 'column', alignItems: 'stretch', gap: 10 }}>
      {rows.map(([label, v, color]) => (
        <div key={label}>
          <div className="spread small" style={{ marginBottom: 4 }}>
            <span>{label}</span><span className="mono">{v || 0}</span>
          </div>
          <div className="progress-wrap"><div className="progress" style={{ width: ((v || 0) / max) * 100 + '%', background: color }} /></div>
        </div>
      ))}
    </div>
  )
}