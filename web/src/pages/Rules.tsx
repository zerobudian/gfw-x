import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { api, fmtTime, type Rule, type Conflict, type RevisionSummary, type RevisionDetail, type DryRunPreview, type ShadowInfo, type RuleChange } from '../api'
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
  const [revisions, setRevisions] = useState<RevisionSummary[]>([])
  const [diffTarget, setDiffTarget] = useState<RevisionDetail | null>(null)
  const [rollbackTarget, setRollbackTarget] = useState<RevisionSummary | null>(null)
  const [shadow, setShadow] = useState<ShadowInfo | null>(null)
  const [shadowRev, setShadowRev] = useState('')
  const [dryContent, setDryContent] = useState('')
  const [dryResult, setDryResult] = useState<DryRunPreview | null>(null)
  const [applyConfirm, setApplyConfirm] = useState(false)

  const refresh = async () => {
    try {
      const [rs, cf] = await Promise.all([api.rules(), api.conflicts()])
      setRules(rs); setConflicts(cf)
    } catch { }
  }
  const refreshRevisions = async () => {
    try {
      const { revisions: rs } = await api.revisions()
      setRevisions(rs)
      setShadowRev((prev) => (prev && rs.some((r) => r.id === prev)) ? prev : (rs[0] ? rs[0].id : ''))
    } catch { }
  }
  const refreshShadow = async () => {
    try { setShadow(await api.shadow()) } catch { }
  }
  useEffect(() => { refresh(); api.presets().then(setPresets).catch(() => {}); refreshRevisions(); refreshShadow() }, [])

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
  const applyPreset = async (p: string) => { await api.applyPreset(p); notify(k('msg.saved')); refresh(); refreshRevisions() }

  const showDiff = async (id: string) => {
    try { setDiffTarget(await api.revision(id)) } catch { }
  }
  const doRollback = async (rev: RevisionSummary) => {
    setRollbackTarget(null)
    try { await api.rollbackRules(rev.id); notify(k('msg.saved')); refresh(); refreshRevisions(); refreshShadow() } catch { }
  }
  const runDry = async () => {
    if (!dryContent.trim()) return
    try { setDryResult(await api.dryRun(dryContent)) }
    catch (e) { setDryResult({ valid: false, incoming_rules: 0, changes: [], conflicts: [], error: e instanceof Error ? e.message : String(e) }) }
  }
  const doApply = async () => {
    setApplyConfirm(false)
    try { await api.applyRules(dryContent); setDryResult(null); setDryContent(''); notify(k('msg.saved')); refresh(); refreshRevisions() } catch { }
  }
  const validateShadow = async () => {
    if (!shadowRev) return
    try { await api.shadowSet(shadowRev); refreshShadow() } catch { }
  }
  const clearShadow = async () => {
    try { await api.shadowSet(''); refreshShadow() } catch { }
  }

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

      <Card title={k('revision.title')} className="" >
        <div style={{ maxHeight: 300, overflow: 'auto', display: 'flex', flexDirection: 'column', gap: 8 }}>
          {revisions.length === 0 && <div className="empty">{k('revision.empty')}</div>}
          {revisions.map((rv) => (
            <div key={rv.id} className="card" style={{ margin: 0, padding: '8px 10px' }}>
              <div className="spread" style={{ marginBottom: 4 }}>
                <span className="mono small">{rv.id}</span>
                <div className="row" style={{ gap: 8 }}>
                  <button className="btn sm" onClick={() => showDiff(rv.id)}>{k('revision.diff')}</button>
                  <button className="btn sm" onClick={() => setRollbackTarget(rv)}>{k('revision.rollback')}</button>
                </div>
              </div>
              <div className="small muted">
                {k('revision.createdAt')}: <span className="mono">{fmtTime(rv.created_at)}</span>
                {' · '}{k('revision.author')}: <span className="mono">{rv.author || '—'}</span>
                {' · '}{k('revision.ruleCount')}: <span className="mono">{rv.rule_count}</span>
              </div>
              <ChangeDots lines={rv.changes} />
            </div>
          ))}
        </div>

        <div className="field" style={{ marginTop: 14 }}>
          <label>{k('revision.dryRun')}</label>
          <textarea value={dryContent} onChange={(e) => setDryContent(e.target.value)} rows={6} style={{ width: '100%', fontFamily: 'monospace' }} placeholder="kind: block&#10;matchers: ..." />
          <div className="row" style={{ marginTop: 8 }}>
            <button className="btn" onClick={runDry}>{k('revision.dryRun')}</button>
            {dryResult && (
              <button className="btn primary" onClick={() => setApplyConfirm(true)}>{k('revision.apply')}</button>
            )}
          </div>
        </div>

        {dryResult && <DryRunView r={dryResult} k={k} />}
      </Card>

      <Card title={k('shadow.title')} className="" >
        <div className="row" style={{ gap: 12, flexWrap: 'wrap', marginBottom: 10 }}>
          <span className={'badge ' + (shadow?.active ? 'observe' : 'neutral')}>
            {shadow?.active ? k('shadow.active') : k('shadow.inactive')}
          </span>
          {shadow?.active && shadow.revision && <span className="mono small">{shadow.revision}</span>}
        </div>
        {shadow?.stats && (
          <div className="row" style={{ gap: 24, flexWrap: 'wrap', marginBottom: 10 }}>
            <div><span className="small muted">{k('shadow.evaluations')}: </span><span className="mono">{shadow.stats.evaluations}</span></div>
            <div><span className="small muted">{k('shadow.wouldAllow')}: </span><span className="mono">{shadow.stats.would_allow}</span></div>
            <div><span className="small muted">{k('shadow.wouldBlock')}: </span><span className="mono">{shadow.stats.would_block}</span></div>
            <div><span className="small muted">{k('shadow.disagreement')}: </span><span className="mono">{shadow.stats.disagreement}</span></div>
          </div>
        )}
        <div className="row" style={{ gap: 8, flexWrap: 'wrap', marginBottom: 10 }}>
          <select value={shadowRev} onChange={(e) => setShadowRev(e.target.value)} style={{ width: 200 }}>
            {revisions.map((r) => <option key={r.id} value={r.id}>{r.id}</option>)}
            {revisions.length === 0 && <option value="">{k('shadow.none')}</option>}
          </select>
          <button className="btn" onClick={validateShadow}>{k('shadow.validate')}</button>
          <button className="btn" onClick={clearShadow}>{k('shadow.clear')}</button>
        </div>
        <div className="small muted">{k('shadow.explain')}</div>
      </Card>

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

      {editor && <Editor k={k} mode={editor.mode} initial={editor.rule} onClose={() => setEditor(null)} onSaved={() => { refresh(); notify(k('msg.saved')); refreshRevisions() }} />}
      {diffTarget && (
        <Modal onClose={() => setDiffTarget(null)}>
          <div className="card-title" style={{ textTransform: 'none' }}>{k('revision.diff')} · {diffTarget.revision.id}</div>
          {diffTarget.changes.length === 0 && <div className="empty">{k('revision.changes')}</div>}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 12 }}>
            {diffTarget.changes.map((c, i) => <ChangeEntry c={c} key={i} />)}
          </div>
          <div className="row spread">
            <button className="btn" onClick={() => setDiffTarget(null)}>{k('label.cancel')}</button>
          </div>
        </Modal>
      )}
      {rollbackTarget && (
        <Modal onClose={() => setRollbackTarget(null)}>
          <div className="card-title" style={{ textTransform: 'none' }}>{k('revision.rollback')} · {rollbackTarget.id}</div>
          <p className="small" style={{ marginBottom: 16 }}>{k('revision.confirmRollback')}</p>
          <div className="row spread">
            <button className="btn" onClick={() => setRollbackTarget(null)}>{k('label.cancel')}</button>
            <button className="btn primary" onClick={() => doRollback(rollbackTarget)}>{k('revision.rollback')}</button>
          </div>
        </Modal>
      )}
      {applyConfirm && (
        <Modal onClose={() => setApplyConfirm(false)}>
          <div className="card-title" style={{ textTransform: 'none' }}>{k('revision.apply')}</div>
          <p className="small" style={{ marginBottom: 16 }}>{k('revision.confirmApply')}</p>
          <div className="row spread">
            <button className="btn" onClick={() => setApplyConfirm(false)}>{k('label.cancel')}</button>
            <button className="btn primary" onClick={doApply}>{k('revision.apply')}</button>
          </div>
        </Modal>
      )}
      {toast && <div className="toast">{toast}</div>}
    </>)
}

function blankRule(): Rule {
  return { id: '', name: '', kind: 'allow', enabled: true, category: '', matchers: [{ field: 'domain', value: '' }], hits: 0, last_hit: '', source: 'dashboard' }
}

function Modal({ children, onClose }: { children: ReactNode; onClose: () => void }) {
  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)', display: 'grid', placeItems: 'center', zIndex: 40 }} onClick={onClose}>
      <div className="card" style={{ width: 560, maxWidth: '92vw', maxHeight: '85vh', overflow: 'auto' }} onClick={(e) => e.stopPropagation()}>
        {children}
      </div>
    </div>
  )
}

function changeColorType(t: string): string {
  if (t === 'added') return 'var(--ok)'
  if (t === 'removed') return 'var(--bad)'
  return 'var(--warn)'
}

function Dot({ color }: { color: string }) {
  return <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, display: 'inline-block', flex: '0 0 auto' }} />
}

function ChangeDots({ lines }: { lines: string[] }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 2, marginTop: 6 }}>
      {lines.map((l, i) => {
        const color = l.startsWith('+') ? 'var(--ok)' : l.startsWith('-') ? 'var(--bad)' : l.startsWith('~') ? 'var(--warn)' : 'var(--muted)'
        return (
          <div key={i} className="row small" style={{ gap: 6 }}>
            <Dot color={color} />
            <span className="mono">{l}</span>
          </div>
        )
      })}
    </div>
  )
}

function ChangeEntry({ c }: { c: RuleChange }) {
  const text = c.type === 'added' ? '+ ' + (c.after || '') : c.type === 'removed' ? '- ' + (c.before || '') : '~ ' + (c.before || '') + ' -> ' + (c.after || '')
  return (
    <div className="row small" style={{ gap: 6 }}>
      <Dot color={changeColorType(c.type)} />
      <span className="mono">{c.rule_id}</span>
      <span className="mono muted">{text}</span>
    </div>
  )
}

function DryRunView({ r, k }: { r: DryRunPreview; k: (s: string) => string }) {
  return (
    <div className="card" style={{ marginTop: 12, background: 'var(--bg-hover)' }}>
      <div className="row" style={{ gap: 12, flexWrap: 'wrap', marginBottom: 8 }}>
        <span className={'badge ' + (r.valid ? 'allow' : 'block')}>{r.valid ? k('revision.valid') : k('revision.invalid')}</span>
        <span className="small muted">{k('revision.incoming')}: <span className="mono">{r.incoming_rules}</span></span>
        <span className="small muted">{k('revision.changes')}: <span className="mono">{r.changes.length}</span></span>
        <span className="small muted">{k('revision.conflicts')}: <span className="mono">{r.conflicts.length}</span></span>
      </div>
      {r.error && <div className="small" style={{ color: 'var(--bad)', marginBottom: 8 }}>{k('revision.error')}: {r.error}</div>}
      {r.changes.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 8 }}>
          {r.changes.map((c, i) => <ChangeEntry c={c} key={i} />)}
        </div>
      )}
      {r.conflicts.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          {r.conflicts.map((cf, i) => (
            <div key={i} className="small mono">{labelOf(cf.a)} ({cf.field}:{cf.value}) ↔ {labelOf(cf.b)}</div>
          ))}
        </div>
      )}
    </div>
  )
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