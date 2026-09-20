import { useEffect, useState } from 'react'
import { api, fmtBytes, fmtRate, fmtUptime, fmtTime, type Rank, type Event } from '../api'
import { Card, Stat, Bar, Doughnut, PALETTE, actionBadge } from '../ui'

export function DashboardPage({ k, status }: { k: (s: string) => string; status: any }) {
  const [events, setEvents] = useState<Event[]>([])
  const [domains, setDomains] = useState<Rank[]>([])
  const [reasons, setReasons] = useState<Rank[]>([])
  const [protocols, setProtocols] = useState<Rank[]>([])

  useEffect(() => {
    let alive = true
    const tick = async () => {
      try {
        const [ev, dom, rea, pro] = await Promise.all([api.events(20), api.topDomains(10), api.topReasons(10), api.protocols()])
        if (!alive) return
        setEvents(ev); setDomains(dom); setReasons(rea); setProtocols(pro)
      } catch { }
    }
    tick()
    const id = window.setInterval(tick, 3000)
    return () => { alive = false; window.clearInterval(id) }
  }, [])

  const c = status?.counters || {}
  const activeFlows = status?.active_flows || 0
  const maxD = domains.reduce((m, d) => Math.max(m, d.count), 0)
  const maxR = reasons.reduce((m, d) => Math.max(m, d.count), 0)
  const protoData = protocols.slice(0, 6).map((p, i) => ({ key: p.key, value: p.count, color: PALETTE[i % PALETTE.length] }))

  return (
    <>
      <div className="mini-stat-row">
        <Stat value={fmtRate(status?.throughput_bps || 0)} label={k('label.throughput')} />
        <Stat value={c.allowed ?? 0} label={k('label.allowed')} />
        <Stat value={c.blocked ?? 0} label={k('label.blocked')} />
        <Stat value={c.unknown ?? 0} label={k('label.unknown')} />
        <Stat value={activeFlows} label={k('label.activeFlows')} />
        <Stat value={c.blocked_today ?? 0} label={k('label.blockedToday')} />
      </div>

      <div className="mini-stat-row">
        <Stat value={fmtUptime(status?.uptime_sec || 0)} label={k('label.uptime')} />
        <Stat value={c.packets ?? 0} label={k('label.packets')} />
        <Stat value={c.flows_seen ?? 0} label={k('label.flows')} />
        <Stat value={fmtBytes((c.bytes_down ?? 0) + (c.bytes_up ?? 0))} label="Σ Bytes" />
        <Stat value={status?.cpu_cores ?? 0} label={k('label.cpu')} />
        <Stat value={(status?.memory_mb || 0).toFixed(0) + ' MB'} label={k('label.mem')} />
      </div>

      <div className="two-col" style={{ marginBottom: 16 }}>
        <Card title={k('label.topDomains')}>
          {domains.length === 0 ? <div className="empty">{k('label.noEvents')}</div> : (
            domains.map((d) => (
              <div key={d.key} style={{ display: 'grid', gridTemplateColumns: '1.6fr 60px 1fr', gap: 10, alignItems: 'center', padding: '5px 0' }}>
                <span className="mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.key}</span>
                <span className="muted small">{d.count}</span>
                <Bar val={d.count} max={maxD} />
              </div>
            ))
          )}
        </Card>

        <Card title={k('label.protocols')}>
          {protoData.length === 0 ? <div className="empty">{k('label.noEvents')}</div> : <Doughnut data={protoData} />}
        </Card>
      </div>

      <div className="two-col" style={{ marginBottom: 16 }}>
        <Card title={k('label.topReasons')}>
          {reasons.length === 0 ? <div className="empty">{k('label.noEvents')}</div> : (
            reasons.map((r) => (
              <div key={r.key} style={{ display: 'grid', gridTemplateColumns: '1.6fr 60px 1fr', gap: 10, alignItems: 'center', padding: '5px 0' }}>
                <span className="mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.key}</span>
                <span className="muted small">{r.count}</span>
                <Bar val={r.count} max={maxR} />
              </div>
            ))
          )}
        </Card>

        <Card title={k('label.vpnDetections')}>
          <div className="stat">
            <div className="stat-value">{status?.detections ?? 0}</div>
            <div className="stat-label">{k('label.actions:observe')}</div>
          </div>
          {status?.log_degraded && <div className="small muted" style={{ marginTop: 10 }}>{status.log_degraded}</div>}
        </Card>
      </div>

      <Card title={k('label.liveEvents')}>
        <div style={{ maxHeight: 420, overflow: 'auto' }}>
          <table>
            <thead>
              <tr>
                <th>{k('label.time')}</th><th>{k('label.source')}</th><th>{k('label.destination')}</th>
                <th>{k('label.protocol')}</th><th>{k('label.domain')}</th><th>{k('label.action')}</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 && <tr><td colSpan={6} className="empty">{k('label.noEvents')}</td></tr>}
              {events.map((e) => (
                <tr key={e.id}>
                  <td className="mono">{fmtTime(e.time)}</td>
                  <td className="mono">{e.src}</td>
                  <td className="mono">{e.dst}</td>
                  <td>{e.proto}</td>
                  <td className="mono">{e.domain || e.sni || '—'}</td>
                  <td>{actionBadge(e.action)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  )
}