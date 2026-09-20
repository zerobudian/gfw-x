import { Card } from '../ui'

export function DevicesPage({ k }: { k: (s: string) => string }) {
  return (
    <Card title={k('label.devices.title')}>
      <div className="empty">{k('label.devices.none')}</div>
      <p className="small muted" style={{ lineHeight: 1.7 }}>
        Devices are inferred from the traffic source addresses on interfaces this gateway inspects.
        The MVP reports per-source aggregation in Traffic; per-device identity, naming and grouping is available in a
        future release.
      </p>
    </Card>
  )
}