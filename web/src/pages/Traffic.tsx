import { useEffect, useState } from 'react'
import { api, fmtBytes, fmtTime, type Rank, type Event, type Status, type DecisionTrace, type TraceMatchedRule } from '../api'
import { Card, Stat, Doughnut, PALETTE, actionBadge } from '../ui'

export function TrafficPage({ k }: { k: (s: string) => string }) {
  const [status, setStatus] = useState<Status | null>(null)
  const [events, setEvents] = useState<Event[]>([])
  const [protocols, setProtocols] = useState<Rank[]>([])
  const [traces, setTraces] = useState<DecisionTrace[]>([])
  const [selected, setSelected] = useState<DecisionTrace | null>(null)

  useEffect(() => {
    let alive = true
    const tick = async () => {
      try {
        const [st, ev, pro, tr] = await Promise.all([api.status(), api.events(100), api.protocols(), api.traces()])
        if (!alive) return
        setStatus(st); setEvents(ev); setProtocols(pro); setTraces(tr.traces || [])
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

      <Card title={k('trace.title')}>
        {traces.length === 0 ? (
          <div className="empty">{k('trace.noTraces')}</div>
        ) : (
          <>
            <div style={{ maxHeight: 320, overflow: 'auto' }}>
              <table>
                <thead>
                  <tr>
                    <th>{k('label.time')}</th><th>{k('label.source')} / {k('label.destination')}</th>
                    <th>{k('trace.protocol')}</th><th>{k('label.domain')}</th>
                    <th>{k('trace.path')}</th><th>{k('label.action')}</th><th>{k('trace.latency')}</th>
                  </tr>
                </thead>
                <tbody>
                  {traces.slice(0, 8).map((t, i) => (
                    <tr key={t.flow_id + '-' + i} style={{ cursor: 'pointer' }} onClick={() => setSelected(t)}>
                      <td className="mono">{fmtTime(t.time)}</td>
                      <td className="mono">{t.src_ip} &gt; {t.dst_ip}</td>
                      <td>{t.proto}</td>
                      <td className="mono">{traceDomain(t)}</td>
                      <td>{pathBadge(t.path, k)}</td>
                      <td>{actionBadge(t.action)}</td>
                      <td className="mono small">{fmtLatency(t.latency_ns)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div style={{ marginTop: 10 }} className="small muted">{k('trace.list')}</div>
            {selected && (
              <div className="card" style={{ marginTop: 12 }}>
                <div className="card-title" style={{ textTransform: 'none' }}>
                  <span>{k('trace.title')} · {traceDomain(selected)}</span>
                  <button className="btn-link" onClick={() => setSelected(null)}>{k('trace.close')}</button>
                </div>
                <TraceDetail t={selected} k={k} />
              </div>
            )}
          </>
        )}
      </Card>
    </>
  )
}

function traceDomain(t: DecisionTrace): string {
  return t.dns_domain || t.sni || t.http_host || (t.dst_ip && t.dst_port ? t.dst_ip + ':' + t.dst_port : (t.dst_ip || '—'))
}

function fmtLatency(ns: number): string {
  if (ns >= 1e6) return (ns / 1e6).toFixed(2) + ' ms'
  if (ns >= 1e3) return (ns / 1e3).toFixed(1) + ' µs'
  return ns + ' ns'
}

function pathBadge(path: string, k: (s: string) => string) {
  void k
  const cls = path === 'fast' ? 'allow' : path === 'bypass' ? 'observe' : path === 'queue_overflow' ? 'reject' : 'block'
  return <span className={'badge ' + cls}>{path}</span>
}

function TraceDetail({ t, k }: { t: DecisionTrace; k: (s: string) => string }) {
  const matched: TraceMatchedRule[] = t.matched_rules || []
  const skipped = t.skipped_conflicts || []
  return (
    <div className="row" style={{ flexDirection: 'column', gap: 12 }}>
      <div className="row" style={{ gap: 18, flexWrap: 'wrap' }}>
        <div><span className="small muted">{k('trace.path')}: </span>{pathBadge(t.path, k)}</div>
        <div><span className="small muted">{k('trace.actionSrc')}: </span><span className="mono">{t.action_source}</span></div>
        <div><span className="small muted">{k('trace.protocol')}: </span>{t.proto}</div>
        <div><span className="small muted">{k('trace.latency')}: </span><span className="mono">{fmtLatency(t.latency_ns)}</span></div>
      </div>
      <div className="row" style={{ gap: 18, flexWrap: 'wrap' }}>
        {t.dns_domain && <div className="mono small">{k('trace.dns')}: {t.dns_domain}</div>}
        {t.sni && <div className="mono small">{k('trace.sni')}: {t.sni}</div>}
        {t.http_host && <div className="mono small">{k('trace.httpHost')}: {t.http_host}</div>}
        {t.dpi_category && <div className="small">{k('label.category')}: {t.dpi_category}</div>}
      </div>
      {t.detector && (
        <div>
          <div className="small muted">{k('trace.detector')}</div>
          <div className="row" style={{ gap: 12 }}>
            <span className="mono">{t.detector}</span>
            {t.detector_confidence != null && (
              <span className="badge observe">{Math.round(t.detector_confidence * 100)}%</span>
            )}
          </div>
          {t.detector_reasons && t.detector_reasons.length > 0 && (
            <ul style={{ margin: '6px 0 0 0', paddingLeft: 18 }}>
              {t.detector_reasons.map((r, i) => <li key={i} className="small">{r}</li>)}
            </ul>
          )}
        </div>
      )}
      {matched.length > 0 && (
        <div>
          <div className="small muted" style={{ marginBottom: 6 }}>{k('trace.matchedRules')}</div>
          <div style={{ maxHeight: 220, overflow: 'auto' }}>
            <table>
              <thead>
                <tr><th>ID</th><th>{k('label.name')} / {k('label.kind')}</th><th>{k('label.category')}</th><th>prio</th><th>{k('label.rule')}</th></tr>
              </thead>
              <tbody>
                {matched.map((m, i) => (
                  <tr key={i}>
                    <td className="mono muted small">{m.id.slice(-6)}</td>
                    <td>{m.name || m.kind}{m.name && m.kind ? ' · ' + m.kind : ''}</td>
                    <td className="small">{m.category || '—'}</td>
                    <td className="mono small">{m.priority}</td>
                    <td className="small mono">{m.label}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      {skipped.length > 0 && (
        <div>
          <div className="small muted" style={{ marginBottom: 4 }}>{k('trace.skipped')}</div>
          {skipped.map((s, i) => (
            <div key={i} className="small mono" style={{ background: 'var(--bg-hover)', padding: '4px 8px', borderRadius: 6, marginBottom: 4 }}>
              {s.rule_a} ↔ {s.rule_b}
            </div>
          ))}
        </div>
      )}
    </div>
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