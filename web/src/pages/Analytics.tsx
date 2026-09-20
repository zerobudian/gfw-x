import { useEffect, useState } from 'react'
import { api, type Rank } from '../api'
import { Card, Bar, Doughnut, PALETTE } from '../ui'

export function AnalyticsPage({ k }: { k: (s: string) => string }) {
  const [doms, setDoms] = useState<Rank[]>([])
  const [reas, setReas] = useState<Rank[]>([])
  const [pros, setPros] = useState<Rank[]>([])
  useEffect(() => {
    let alive = true
    const tick = () => api.analytics().then((a) => alive && (setDoms(a.top_domains), setReas(a.top_reasons), setPros(a.protocols))).catch(() => {})
    tick()
    const id = window.setInterval(tick, 3000)
    return () => { alive = false; window.clearInterval(id) }
  }, [])

  const maxD = doms.reduce((m, d) => Math.max(m, d.count), 0)
  const maxR = reas.reduce((m, d) => Math.max(m, d.count), 0)
  const protoData = pros.slice(0, 6).map((p, i) => ({ key: p.key, value: p.count, color: PALETTE[i % PALETTE.length] }))

  return (
    <div className="two-col">
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <Card title={k('label.topDomains')}>
          {doms.map((d) => (
            <div key={d.key} style={{ display: 'grid', gridTemplateColumns: '1.6fr 60px 1fr', gap: 10, alignItems: 'center', padding: '5px 0' }}>
              <span className="mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.key}</span>
              <span className="muted small">{d.count}</span>
              <Bar val={d.count} max={maxD} />
            </div>
          ))}
        </Card>
        <Card title={k('label.topReasons')}>
          {reas.map((r) => (
            <div key={r.key} style={{ display: 'grid', gridTemplateColumns: '1.6fr 60px 1fr', gap: 10, alignItems: 'center', padding: '5px 0' }}>
              <span className="mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.key}</span>
              <span className="muted small">{r.count}</span>
              <Bar val={r.count} max={maxR} />
            </div>
          ))}
        </Card>
      </div>
      <Card title={k('label.protocols')}>
        {protoData.length === 0 ? <div className="empty">{k('label.noEvents')}</div> : <Doughnut data={protoData} />}
      </Card>
    </div>
  )
}