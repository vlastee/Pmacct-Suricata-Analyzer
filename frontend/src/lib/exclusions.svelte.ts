// Global trusted list (alert exclusions), cached client-side so IP labels can show status.
// Matching mirrors the server: exact IP, CIDR containment, hostname globs against known names.
import { api, type Exclusion } from './api'

function ipToBits(ip: string): bigint | null {
  if (ip.includes(':')) {
    const [head, tail = ''] = ip.split('::')
    const h = head ? head.split(':') : []
    const t = tail ? tail.split(':') : []
    if (h.length + t.length > 8 || (!ip.includes('::') && h.length !== 8)) return null
    const groups = [...h, ...Array(8 - h.length - t.length).fill('0'), ...t]
    let v = 0n
    for (const g of groups) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null
      v = (v << 16n) | BigInt(parseInt(g, 16))
    }
    return v
  }
  const p = ip.split('.')
  if (p.length !== 4) return null
  let v = 0n
  for (const s of p) {
    const n = Number(s)
    if (!/^\d+$/.test(s) || n > 255) return null
    v = (v << 8n) | BigInt(n)
  }
  return v
}

export function ipInCidr(ip: string, cidr: string): boolean {
  const [net, bitsStr] = cidr.split('/')
  const bits = Number(bitsStr)
  const a = ipToBits(ip), n = ipToBits(net)
  if (a === null || n === null || isNaN(bits)) return false
  const v6 = net.includes(':')
  if (v6 !== ip.includes(':')) return false
  const width = v6 ? 128 : 32
  const shift = BigInt(width - bits)
  return (a >> shift) === (n >> shift)
}

function globToRe(pattern: string): RegExp {
  return new RegExp('^' + pattern.split('*').map(s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$', 'i')
}

class Exclusions {
  items = $state<Exclusion[]>([])
  loaded = $state(false)

  async refresh() {
    try { this.items = (await api.exclusions()).items; this.loaded = true } catch { /* not authed yet */ }
  }
  matchIP(ip: string): Exclusion | null {
    for (const e of this.items) {
      if (e.kind === 'ip' && e.pattern === ip) return e
      if (e.kind === 'cidr' && ipInCidr(ip, e.pattern)) return e
    }
    return null
  }
  matchNames(names: string[] | null | undefined): Exclusion | null {
    if (!names?.length) return null
    for (const e of this.items) {
      if (e.kind !== 'name') continue
      const re = globToRe(e.pattern)
      if (names.some(n => re.test(n.replace(/\.$/, '')))) return e
    }
    return null
  }
  match(ip: string, names?: string[] | null): Exclusion | null { return this.matchIP(ip) ?? this.matchNames(names) }
  async add(pattern: string, note = '') { const r = await api.addExclusion(pattern, note); await this.refresh(); return r }
  async remove(id: number) { await api.deleteExclusion(id); await this.refresh() }
}

export const exclusions = new Exclusions()
