import { useEffect, useState } from 'react'
import { fetchAlerts, fetchSummary } from './api'
import type { Alert, AlertCount } from './types'
import AlertChart from './AlertChart'
function App() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [summary, setSummary] = useState<AlertCount[]>([])
  const [kind, setKind] = useState<string>('')
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchSummary().then(setSummary).catch((e: Error) => setError(e.message))
  }, [])

  useEffect(() => {
    fetchAlerts(kind || undefined).then(setAlerts).catch((e: Error) => setError(e.message))
  }, [kind])

  return (
    <main>
      <h1>NetWatch Dashboard</h1>
      {error && <p className="error">{error}</p>}

      <section className="cards">
        {summary.map((s) => (
          <button
            key={s.kind}
            className={`card ${kind === s.kind ? 'active' : ''}`}
            onClick={() => setKind(kind === s.kind ? '' : s.kind)}
          >
            <span className="count">{s.count}</span>
            <span className="kind">{s.kind}</span>
          </button>
        ))}
      </section>
      <AlertChart data={summary} />
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Type</th>
            <th>Source</th>
            <th>Target</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((a, i) => (
            <tr key={i}>
              <td>{new Date(a.time).toLocaleString()}</td>
              <td>{a.kind}</td>
              <td>{a.source_ip ?? '-'}</td>
              <td>{a.target_ip ?? '-'}</td>
              <td>{a.message}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </main>
  )
}

export default App
