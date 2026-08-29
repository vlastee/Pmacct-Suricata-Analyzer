export function fmtBytes(n: number | null | undefined, digits = 1): string {
  if (n == null) return '–'
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(i === 0 ? 0 : digits)} ${units[i]}`
}

export function fmtRate(bytes: number, seconds: number): string {
  if (!seconds) return '–'
  const bps = (bytes * 8) / seconds
  const units = ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s']
  let i = 0
  let v = bps
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i++ }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

export function fmtNum(n: number | null | undefined): string {
  if (n == null) return '–'
  return new Intl.NumberFormat().format(n)
}

export function fmtCompact(n: number | null | undefined): string {
  if (n == null) return '–'
  return new Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 }).format(n)
}

export function fmtTime(iso: string | null | undefined, withDate = true): string {
  if (!iso) return '–'
  const d = new Date(iso)
  if (isNaN(d.getTime())) return '–'
  return withDate
    ? d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
    : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
}

export function fmtAgo(iso: string | null | undefined): string {
  if (!iso) return 'never'
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 60) return `${Math.round(s)}s ago`
  if (s < 3600) return `${Math.round(s / 60)}m ago`
  if (s < 86400) return `${Math.round(s / 3600)}h ago`
  return `${Math.round(s / 86400)}d ago`
}

export function flag(cc: string | null | undefined): string {
  if (!cc || cc.length !== 2 || cc === '??') return ''
  const base = 0x1f1e6
  return String.fromCodePoint(base + cc.toUpperCase().charCodeAt(0) - 65, base + cc.toUpperCase().charCodeAt(1) - 65)
}

export function pct(part: number, total: number): string {
  if (!total) return '0%'
  return `${((100 * part) / total).toFixed(1)}%`
}
