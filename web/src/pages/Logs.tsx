import { useEffect, useState } from 'react'
import { api, fmtBytes, fmtTime, type Event } from '../api'
import { Card } from '../ui'

export function LogsPage({ k }: { k: (s: string) => string }) {
  const [events, setEvents] = useState<Event[]>([])
  const [filter, setFilter] = useState('')
  useEffect(() => {
    let alive = true
    const tick = () => api.events(500).then((e) => alive && setEvents(e)).catch(() => {})
    tick()
    const id = window.setInterval(tick, 3000)
    return () => { alive = false; window.clearInterval(id) }
  }, [])

  const f = filter.toLowerCase()
  const rows = events.filter((e) => !f || (e.src + e.dst + e.proto + (e.domain || '') + e.action).toLowerCase().includes(f))

  return (
    <Card title={k('label.logs.title')}>
      <div style={{ marginBottom: 12 }}>
        <input placeholder={k('label.search')} value={filter} onChange={(e) => setFilter(e.target.value)} style={{ maxWidth: 320 }} />
      </div>
      <div style={{ maxHeight: 640, overflow: 'auto' }}>
        <table>
          <thead>
            <tr>
              <th>{k('label.time')}</th><th>{k('label.source')}</th><th>{k('label.destination')}</th>
              <th>{k('label.protocol')}</th><th>{k('label.domain')}</th><th>{k('label.action')}</th>
              <th>↑/↓</th><th>dur</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && <tr><td colSpan={8} className="empty">{k('label.noEvents')}</td></tr>}
            {rows.map((e) => (
              <tr key={e.id}>
                <td className="mono">{fmtTime(e.time)}</td>
                <td className="mono">{e.src}</td>
                <td className="mono">{e.dst}</td>
                <td>{e.proto}</td>
                <td className="mono">{e.domain || e.sni || '—'}</td>
                <td>{e.action}</td>
                <td className="mono small">{fmtBytes(e.bytes_up)}/{fmtBytes(e.bytes_down)}</td>
                <td className="mono small">{e.duration_sec ? e.duration_sec.toFixed(1) + 's' : ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}