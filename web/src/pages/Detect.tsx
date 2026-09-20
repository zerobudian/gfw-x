import { useEffect, useState } from 'react'
import { api, type DetectInfo } from '../api'
import { Card, Stat } from '../ui'

export function DetectPage({ k }: { k: (s: string) => string }) {
  const [info, setInfo] = useState<DetectInfo | null>(null)
  useEffect(() => {
    let alive = true
    const tick = () => api.detect().then((d) => alive && setInfo(d)).catch(() => {})
    tick()
    const id = window.setInterval(tick, 2000)
    return () => { alive = false; window.clearInterval(id) }
  }, [])

  return (
    <>
      <div className="mini-stat-row">
        <Stat value={info?.enabled ? 'ON' : 'OFF'} label={k('label.detect.enabled')} />
        <Stat value={info ? (info.threshold * 100).toFixed(0) + '%' : '—'} label={k('label.detect.confidence')} />
        <Stat value={info?.auto_apply ? 'RATE_LIMIT+REJECT' : 'OBSERVE'} label={k('label.detect.auto')} />
        <Stat value={info?.detections || 0} label={k('label.vpnDetections')} />
      </div>

      <Card title={k('label.detect.title')}>
        <p style={{ color: 'var(--text-soft)', lineHeight: 1.7 }}>
          Detection engines: WireGuard · OpenVPN · SOCKS4/5 · HTTP CONNECT · QUIC/HTTP3 · unknown encrypted tunnel.
          Detection only reports a recommendation; the policy layer decides the final action. Low-confidence results are
          never blocked by default.
        </p>
        <p className="small" style={{ color: 'var(--text-muted)' }}>
          Behavioral features: packet size distribution · direction sequence · connection lifetime · keepalive pattern · burst interval · up/down ratio.
        </p>
      </Card>
    </>
  )
}