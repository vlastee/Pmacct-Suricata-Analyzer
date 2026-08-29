// Tiny hash router: #/path?query. Keeps the global time range in the query so links are shareable.
export interface Route { path: string; parts: string[]; query: URLSearchParams }

function parse(): Route {
  const h = location.hash.startsWith('#') ? location.hash.slice(1) : location.hash
  const [p, q = ''] = h.split('?')
  const path = p || '/'
  return { path, parts: path.split('/').filter(Boolean), query: new URLSearchParams(q) }
}

class Router {
  route = $state<Route>(parse())
  constructor() {
    window.addEventListener('hashchange', () => { this.route = parse() })
  }
  href(path: string, query?: Record<string, string | undefined>): string {
    const q = new URLSearchParams(this.route.query)
    // keep the global range unless overridden
    for (const k of Array.from(q.keys())) if (k !== 'since' && k !== 'until') q.delete(k)
    if (query) for (const [k, v] of Object.entries(query)) v === undefined ? q.delete(k) : q.set(k, v)
    const s = q.toString()
    return `#${path}${s ? `?${s}` : ''}`
  }
  go(path: string, query?: Record<string, string | undefined>) { location.hash = this.href(path, query).slice(1) }
  setQuery(patch: Record<string, string | undefined>) {
    const q = new URLSearchParams(this.route.query)
    for (const [k, v] of Object.entries(patch)) v === undefined || v === '' ? q.delete(k) : q.set(k, v)
    const s = q.toString()
    location.hash = `${this.route.path}${s ? `?${s}` : ''}`
  }
}

export const router = new Router()

export const RANGES: { label: string; since: string }[] = [
  { label: '15m', since: '15m' }, { label: '1h', since: '1h' }, { label: '6h', since: '6h' },
  { label: '24h', since: '24h' }, { label: '7d', since: '168h' }, { label: '30d', since: '720h' },
]

export function currentRange(): { since: string; until?: string } & Record<string, string | undefined> {
  const q = router.route.query
  return { since: q.get('since') ?? '24h', until: q.get('until') ?? undefined }
}
