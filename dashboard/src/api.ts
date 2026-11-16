import type { Alert, AlertCount } from './types'

export async function fetchAlerts(kind?: string): Promise<Alert[]> {
  const url = kind ? `/alerts?kind=${encodeURIComponent(kind)}` : '/alerts'
  const res = await fetch(url)
  if (!res.ok) throw new Error(`API error: ${res.status}`)
  return res.json()
}

export async function fetchSummary(): Promise<AlertCount[]> {
  const res = await fetch('/alerts/summary')
  if (!res.ok) throw new Error(`API error: ${res.status}`)
  return res.json()
}
