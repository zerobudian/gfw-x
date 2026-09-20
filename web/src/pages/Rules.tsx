import { useEffect, useMemo, useState } from 'react'
import { api, fmtTime, type Rule, type Conflict } from '../api'
import { Card, kindBadge } from '../ui'

const FIELDS = ['domain', 'domain_suffix', 'wildcard', 'ip', 'cidr', 'asn', 'protocol', 'dns', 'sni', 'port', 'category']
const KINDS = ['allow', 'block', 'observe', 'ratelimit']

function labelOf(r: Rule): string {
  if (r.name) return r.name
  if (r.matchers.length) return r.matchers[0].field + ':' + r.matchers[0].value
  return r.id
}

export function RulesPage({ k }: { k: (s: string) => string }) {
  const [rules, setRules] = useState<Rule[]>([])
  const [presets, setPresets] = useState<Record<string, string>>({})
  const [conflicts, setConflicts] = useState<Conflict[]>([])
  const [q, setQ] = useState('')
  const [catFilter, setCatFilter] = useState('')
  const [editor, setEditor] = useState<{ mode: 'new' | 'edit'; rule: Rule } | null>(null)
  const [toast, setToast] = useState('')

  const refresh = async () => {
    try {
      const [rs, cf] = await Promise.all([api.rules(), api.conflicts()])
      setRules(rs); setConflicts(cf)
    } catch { }
  }
  useEffect(() => { refresh(); api.presets().then(setPresets).catch(() => {}) }, [])

  const cats = useMemo(() => Array.from(new Set(rules.map((r) => r.category).filter(Boolean))), [rules])
  const filtered = rules.filter((r) => {
    const lb = labelOf(r).toLowerCase()
    if (q && !lb.includes(q.toLowerCase()) && !r.id.toLowerCase().includes(q.toLowerCase()) && !r.category.toLowerCase().includes(q.toLowerCase()) && !r.matchers.some((m) => m.value.toLowerCase().includes(q.toLowerCase()))) return false
    if (catFilter && r.category !== catFilter) return false
    return true
  })

  const notify = (m: string) => { setToast(m); window.setTimeout(() => setToast(''), 2200) }

  const toggle = async (r: Rule) => {
    await api.updateRule({ ...r, enabled: !r.enabled }); refresh()
  }
  const del = async (r: Rule) => { await api.deleteRule(r.id); notify(k('msg.saved')); refresh() }
  const dup = async (r: Rule) => {
    const copy = { ...r, id: '', name: r.name + ' (copy)' }
    await api.addRule(copy); refresh()
  }
  const applyPreset = async (p: string) => { await api.applyPreset(p); notify(k('msg.saved')); refresh() }

  return (
    <>
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-title">{k('label.presets')}</div>
        <div className="preset-grid">
          {Object.entries(presets).map(([name, desc]) => (
            <button key={name} className="pill" title={desc} onClick={() => applyPreset(name)}>{name}</button>
          ))}
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="spread" style={{ flexWrap: 'wrap' }}>
          <div className="row">
            <input placeholder={k('label.search')} value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 220 }} />
            <select value={catFilter} onChange={(e) => setCatFilter(e.target.value)} style={{ width: 180 }}>
              <option value="">{k('label.category')}</option>
              {cats.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>
          <div className="row">
            {conflicts.length > 0 && <span className="badge neutral">{k('label.ruleConflict')}: {conflicts.length}</span>}
            <button className="btn primary" onClick={() => setEditor({ mode: 'new', rule: blankRule() })}>{k('label.addRule')}</button>
          </div>
        </div>
      </div>

      {conflicts.length > 0 && (
        <Card title={k('label.ruleConflict')} className="" >
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {conflicts.map((cf, i) => (
              <div key={i} className="small mono" style={{ background: 'var(--bg-hover)', padding: '8px 10px', borderRadius: 8 }}>
                {labelOf(cf.a)} ({cf.field}:{cf.value}) ↔ {labelOf(cf.b)}
              </div>
            ))}
          </div>
        </Card>
      )}

      <Card title={k('label.rules.collection') + ' · ' + filtered.length}>
        <div style={{ maxHeight: 600, overflow: 'auto' }}>
          <table>
            <thead>
              <tr>
                <th>#</th><th>{k('label.name')}</th><th>{k('label.kind')}</th><th>{k('label.category')}</th>
                <th>{k('label.matchers')}</th><th>{k('label.hits')}</th><th>{k('label.lastHit')}</th><th>{k('label.enabled')}</th><th></th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 && <tr><td colSpan={9} className="empty">{k('label.noEvents')}</td></tr>}
              {filtered.map((r) => (
                <tr key={r.id}>
                  <td className="mono muted">{r.id.slice(-6)}</td>
                  <td>{r.name || labelOf(r)}</td>
                  <td>{kindBadge(r.kind)}</td>
                  <td className="small">{r.category || '—'}</td>
                  <td className="mono small">{r.matchers.map((m) => m.field + ':' + m.value).join(', ')}</td>
                  <td className="mono">{r.hits}</td>
                  <td className="mono small">{r.last_hit ? fmtTime(r.last_hit) : '—'}</td>
                  <td><button className={'switch' + (r.enabled ? ' on' : '')} onClick={() => toggle(r)} /></td>
                  <td>
                    <div className="row">
                      <button className="btn-link" onClick={() => setEditor({ mode: 'edit', rule: r })}>{k('label.edit')}</button>
                      <button className="btn-link" onClick={() => dup(r)}>{k('label.duplicate')}</button>
                      <button className="btn-link" style={{ color: 'var(--bad)' }} onClick={() => del(r)}>{k('label.delete')}</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {editor && <Editor k={k} mode={editor.mode} initial={editor.rule} onClose={() => setEditor(null)} onSaved={() => { refresh(); notify(k('msg.saved')) }} />}
      {toast && <div className="toast">{toast}</div>}
    </>
  )
}

function blankRule(): Rule {
  return { id: '', name: '', kind: 'allow', enabled: true, category: '', matchers: [{ field: 'domain', value: '' }], hits: 0, last_hit: '', source: 'dashboard' }
}

function Editor({ k, mode, initial, onClose, onSaved }: { k: (s: string) => string; mode: 'new' | 'edit'; initial: Rule; onClose: () => void; onSaved: () => void }) {
  const [r, setR] = useState<Rule>({ ...initial, matchers: [...initial.matchers] })
  const save = async () => {
    if (mode === 'new') await api.addRule(r); else await api.updateRule(r)
    onSaved(); onClose()
  }
  const update = (patch: Partial<Rule>) => setR((p) => ({ ...p, ...patch }))
  const setMatch = (i: number, m: Partial<{ field: string; value: string }>) => {
    const ms = r.matchers.map((mm, j) => (i === j ? { ...mm, ...m } : mm))
    update({ matchers: ms })
  }
  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)', display: 'grid', placeItems: 'center', zIndex: 40 }}>
      <div className="card" style={{ width: 520, maxWidth: '92vw' }}>
        <div className="card-title" style={{ textTransform: 'none' }}>{mode === 'new' ? k('label.addRule') : k('label.editRule')}</div>
        <div className="field"><label>{k('label.name')}</label><input value={r.name} onChange={(e) => update({ name: e.target.value })} /></div>
        <div className="row" style={{ gap: 12 }}>
          <div className="field" style={{ flex: 1 }}><label>{k('label.kind')}</label>
            <select value={r.kind} onChange={(e) => update({ kind: e.target.value as Rule['kind'] })}>
              {KINDS.map((kk) => <option key={kk} value={kk}>{kk.toUpperCase()}</option>)}
            </select>
          </div>
          <div className="field" style={{ flex: 1 }}><label>{k('label.category')}</label><input value={r.category} onChange={(e) => update({ category: e.target.value })} /></div>
        </div>
        <div className="field">
          <label>{k('label.matchers')}</label>
          {r.matchers.map((m, i) => (
            <div key={i} className="row" style={{ marginBottom: 8 }}>
              <select value={m.field} onChange={(e) => setMatch(i, { field: e.target.value })} style={{ width: 170 }}>
                {FIELDS.map((f) => <option key={f} value={f}>{f}</option>)}
              </select>
              <input value={m.value} onChange={(e) => setMatch(i, { value: e.target.value })} placeholder="github.com" />
              <button className="btn sm" onClick={() => setR({ ...r, matchers: r.matchers.filter((_, j) => j !== i) })}>{k('label.delete')}</button>
            </div>
          ))}
          <button className="btn sm" onClick={() => setR({ ...r, matchers: [...r.matchers, { field: 'domain', value: '' }] })}>+</button>
        </div>
        <div className="field"><label>{k('label.comment')}</label><input value={r.comment || ''} onChange={(e) => update({ comment: e.target.value })} /></div>
        <div className="row spread">
          <button className="btn" onClick={onClose}>{k('label.cancel')}</button>
          <button className="btn primary" onClick={save}>{k('label.save')}</button>
        </div>
      </div>
    </div>
  )
}