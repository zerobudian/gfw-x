import { useEffect } from 'react'
import { LANG_KEY, THEME_KEY, type Lang, type Theme } from '../i18n'
import { Card } from '../ui'

export function SettingsPage({ k, theme, lang, onTheme, onLang }: {
  k: (s: string) => string
  theme: Theme
  lang: Lang
  onTheme: (t: Theme) => void
  onLang: (l: Lang) => void
}) {
  // ensure DOM theme + lang applied immediately on change
  useEffect(() => {
    if (theme === 'system') {
      document.documentElement.dataset.theme = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
    } else {
      document.documentElement.dataset.theme = theme
    }
  }, [theme])

  const setTheme = (t: Theme) => { localStorage.setItem(THEME_KEY, t); onTheme(t) }
  const setLang = (l: Lang) => { localStorage.setItem(LANG_KEY, l); onLang(l) }

  const themes: Theme[] = ['system', 'light', 'dark']
  const langs: Lang[] = ['system', 'zh-CN', 'en']

  return (
    <div className="two-col">
      <Card title={k('label.theme')}>
        <div className="row" style={{ flexWrap: 'wrap' }}>
          {themes.map((t) => (
            <button key={t} className={'pill' + (theme === t ? ' active' : '')} onClick={() => setTheme(t)}>
              {k(t === 'system' ? 'label.system' : 'label.' + t)}
            </button>
          ))}
        </div>
      </Card>

      <Card title={k('label.language')}>
        <div className="row" style={{ flexWrap: 'wrap' }}>
          {langs.map((l) => (
            <button key={l} className={'pill' + (lang === l ? ' active' : '')} onClick={() => setLang(l)}>
              {l === 'system' ? k('label.system') : l}
            </button>
          ))}
        </div>
      </Card>
    </div>
  )
}