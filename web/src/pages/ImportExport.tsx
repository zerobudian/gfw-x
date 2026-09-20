import { useRef, useState } from 'react'
import { api, rawUrl, type Rule } from '../api'
import { Card } from '../ui'

export function ImportPage({ k }: { k: (s: string) => string }) {
  const [content, setContent] = useState('')
  const [preview, setPreview] = useState<{ parsed: Rule[]; conflicts: string[] } | null>(null)
  const [toast, setToast] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)

  const notify = (m: string) => { setToast(m); window.setTimeout(() => setToast(''), 2000) }

  const loadFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => setContent(String(reader.result || ''))
    reader.readAsText(file)
  }

  const run = async (apply: boolean) => {
    if (!content.trim()) { notify(k('msg.error')); return }
    if (apply) {
      try {
        const r = await api.importRules(content)
        notify(`${k('msg.imported')}: ${r.imported}`)
        setPreview(null)
      } catch (err: any) {
        setPreview({ parsed: [], conflicts: [err.message] })
        notify(err.message || k('msg.error'))
      }
    } else {
      try {
        const r = await api.importPreview(content)
        setPreview({ parsed: r.parsed, conflicts: r.conflicts.map((c) => `${c.value}`) })
      } catch (err: any) { notify(err.message || k('msg.error')) }
    }
  }

  return (
    <div className="two-col">
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <Card title={k('label.import.title')}>
          <p className="small muted">{k('label.import.rules')}</p>
          <div className="field">
            <label>{k('label.import.paste')}</label>
            <textarea rows={12} value={content} onChange={(e) => setContent(e.target.value)} placeholder={'ALLOW github.com\nALLOW *.pages.dev\nBLOCK example.com\nBLOCK_CATEGORY gambling'} />
          </div>
          <div className="row">
            <input ref={fileRef} type="file" hidden onChange={loadFile} />
            <button className="btn" onClick={() => fileRef.current?.click()}>↑ {'Upload'}</button>
            <button className="btn" onClick={() => run(false)}>{k('label.preview')}</button>
            <button className="btn primary" onClick={() => run(true)}>{k('label.apply')} (import)</button>
          </div>
          {preview && (
            <div style={{ marginTop: 12 }}>
              {preview.parsed.length > 0 && (
                <div className="small">
                  <div className="muted" style={{ marginBottom: 6 }}>Parsed: {preview.parsed.length}</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {preview.parsed.slice(0, 40).map((p, i) => (
                      <span key={i} className={'badge ' + (p.kind === 'allow' ? 'allow' : p.kind === 'block' ? 'block' : 'observe')}>{p.kind}:{p.matchers.map((m) => m.value).join(',')}</span>
                    ))}
                  </div>
                </div>
              )}
              {preview.conflicts.length > 0 && (
                <div className="small" style={{ marginTop: 10 }}>
                  <div className="muted">⚠ Conflicts: {preview.conflicts.length}</div>
                  {preview.conflicts.slice(0, 10).map((c, i) => <div key={i} className="mono" style={{ color: 'var(--bad)' }}>{c}</div>)}
                </div>
              )}
            </div>
          )}
        </Card>
      </div>

      <Card title={k('label.export')}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <ExportLink label={k('label.export.current') + ' (YAML)'} url={rawUrl('/rules/export', { format: 'yaml' })} />
          <ExportLink label={k('label.export.current') + ' (JSON)'} url={rawUrl('/rules/export', { format: 'json' })} />
          <ExportLink label={k('label.export.current') + ' (TXT)'} url={rawUrl('/rules/export', { format: 'txt' })} />
          <ExportLink label={k('label.export.zip')} url={rawUrl('/export', {})} />
          <a className="btn" style={{ textAlign: 'center' }} href={rawUrl('/export', { redact: '1' })} download>{k('label.redact')} · ZIP</a>
        </div>
      </Card>
      {toast && <div className="toast">{toast}</div>}
    </div>
  )
}

function ExportLink({ label, url }: { label: string; url: string }) {
  return <a className="btn" style={{ textAlign: 'center' }} href={url} download>{label}</a>
}