// Reusable client-side column sorting for tables. Create one Sorter per table and pass it to <Th>.
export type SortDir = 'asc' | 'desc'

function ipKey(s: string): string | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s)
  if (!m) return null
  return m.slice(1).map(o => o.padStart(3, '0')).join('.')
}

function cmp(a: unknown, b: unknown): number {
  if (typeof a === 'number' && typeof b === 'number') return a - b
  if (typeof a === 'boolean' && typeof b === 'boolean') return Number(a) - Number(b)
  const sa = String(a), sb = String(b)
  const ia = ipKey(sa), ib = ipKey(sb)
  if (ia !== null && ib !== null) return ia < ib ? -1 : ia > ib ? 1 : 0
  return sa.localeCompare(sb, undefined, { numeric: true, sensitivity: 'base' })
}

export class Sorter {
  key = $state('')
  dir = $state<SortDir>('desc')

  constructor(key: string, dir: SortDir = 'desc') {
    this.key = key
    this.dir = dir
  }

  /** Click handler: same column flips direction; a new column starts desc for numbers, asc for text. */
  toggle(key: string, numeric = false) {
    if (this.key === key) this.dir = this.dir === 'asc' ? 'desc' : 'asc'
    else { this.key = key; this.dir = numeric ? 'desc' : 'asc' }
  }

  /** Returns a sorted copy. `get` resolves a column value; defaults to item[key]. Nulls always sort last. */
  apply<T>(items: T[], get: (item: T, key: string) => unknown = (it, k) => (it as any)[k]): T[] {
    const key = this.key
    if (!key) return items
    const mul = this.dir === 'asc' ? 1 : -1
    return items
      .map((it, i) => ({ it, i, v: get(it, key) }))
      .sort((x, y) => {
        const xn = x.v == null || x.v === '', yn = y.v == null || y.v === ''
        if (xn || yn) return xn && yn ? x.i - y.i : xn ? 1 : -1
        return mul * cmp(x.v, y.v) || x.i - y.i
      })
      .map(x => x.it)
  }
}
