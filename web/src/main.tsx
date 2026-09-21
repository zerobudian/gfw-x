import { createRoot } from 'react-dom/client'
import { App } from './App'
import { SafeGate } from './safe/SafeGate'
import './styles.css'

const el = document.getElementById('root')
if (el) createRoot(el).render(
  <SafeGate>
    <App />
  </SafeGate>
)