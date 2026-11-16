export interface Alert {
  time: string
  kind: string
  source_ip: string | null
  target_ip: string | null
  message: string
}

export interface AlertCount {
  kind: string
  count: number
}
