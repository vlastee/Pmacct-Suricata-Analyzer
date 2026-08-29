<script lang="ts">
  import { api, type HostStat } from '../lib/api'
  import { currentRange, router } from '../lib/router.svelte'
  import { fmtBytes, fmtCompact, fmtTime } from '../lib/format'
  import IPLabel from '../lib/components/IPLabel.svelte'
  import Loading from '../lib/components/Loading.svelte'

  let { reloadKey }: { reloadKey: number } = $props()
  let items = $state<HostStat[]>([])
  let total = $state(0)
  let error = $state<string | null>(null)
  let loading = $state(false)
  const limit = 50

  let q = $derived(router.route.query)
  let scope = $derived(q.get('scope') ?? 'all')
  let sort = $derived(q.get('sort') ?? 'bytes')
  let order = $derived(q.get('order') ?? 'desc')
  let page = $derived(Number(q.get('page') ?? '0'))
  let search = $state('')
  $effect(() => { search = q.get('q') ?? '' })

  async function load() {
    loading = true; error = null
    try {
      const r = await api.hosts(currentRange(), { scope: scope === 'all' ? undefined : scope, sort, order, q: q.get('q') ?? undefined,
        country: q.get('country') ?? undefined, asn: q.get('asn') ?? undefined, limit, offset: page * limit })
      items = r.items; total = r.total
    } catch (e: any) { error = e.message } finally { loading = false }
  }
  $effect(() => { void reloadKey; void q.toString(); load() })

  const cols: { key: string; label: string }[] = [
    { key: 'bytes', label: 'Total' }, { key: 'bytes_in', label: 'In' }, { key: 'bytes_out', label: 'Out' },
    { key: 'flows', label: 'Flows' }, { key: 'peers', label: 'Peers' }, { key: 'last_seen', label: 'Last seen' },
  ]
  function setSort(k: string) {
    if (k === sort) router.setQuery({ order: order === 'desc' ? 'asc' : 'desc', page: undefined })
    else router.setQuery({ sort: k, order: k === 'ip' ? 'asc' : 'desc', page: undefined })
  }
  function submitSearch(e: Event) { e.preventDefault(); router.setQuery({ q: search || undefined, page: undefined }) }
</script>

<div class="row" style="margin-bottom:1rem">
  <div class="seg">
    {#each [['all', 'All'], ['local', 'Local'], ['external', 'External']] as [k, l]}
      <button class:active={scope === k} onclick={() => router.setQuery({ scope: k === 'all' ? undefined : k, page: undefined })}>{l}</button>
    {/each}
  </div>
  <form onsubmit={submitSearch} class="row">
    <input placeholder="Search IP, hostname, org…" bind:value={search} size="30" />
    <button type="submit">Search</button>
  </form>
  {#if q.get('country')}<span class="badge">country: {q.get('country')} <button class="x" onclick={() => router.setQuery({ country: undefined })}>×</button></span>{/if}
  {#if q.get('asn')}<span class="badge">{q.get('asn')} <button class="x" onclick={() => router.setQuery({ asn: undefined })}>×</button></span>{/if}
  <span class="spacer"></span>
  <span class="muted small">{total} hosts</span>
</div>

<Loading {error} loading={loading && !items.length} />
<div class="card overflow">
  <table>
    <thead><tr>
      <th class="sortable" class:active={sort === 'ip'} onclick={() => setSort('ip')}>Host{sort === 'ip' ? (order === 'desc' ? ' ▾' : ' ▴') : ''}</th>
      <th>Location / organisation</th>
      {#each cols as c}<th class="num sortable" class:active={sort === c.key} onclick={() => setSort(c.key)}>{c.label}{sort === c.key ? (order === 'desc' ? ' ▾' : ' ▴') : ''}</th>{/each}
    </tr></thead>
    <tbody>
      {#each items as h (h.ip)}
        <tr>
          <td><IPLabel ip={h.ip} nickname={h.nickname} local={h.local} info={h.info} names={h.names} risk={h.risk} /></td>
          <td class="small secondary">
            {#if h.info}
              {[h.info.city, h.info.region, h.info.country].filter(Boolean).join(', ')}
              {#if h.info.asn}<span class="muted"> · <a href={router.href('/hosts', { scope: 'external', asn: h.info.asn })}>{h.info.asn}</a> {h.info.as_org ?? ''}</span>{/if}
            {:else if !h.local}<span class="muted">not enriched yet</span>{/if}
          </td>
          <td class="num">{fmtBytes(h.bytes)}</td><td class="num">{fmtBytes(h.bytes_in)}</td><td class="num">{fmtBytes(h.bytes_out)}</td>
          <td class="num">{fmtCompact(h.flows)}</td><td class="num">{h.peers}</td><td class="num">{fmtTime(h.last_seen)}</td>
        </tr>
      {:else}
        <tr><td colspan="8" class="empty">No hosts</td></tr>
      {/each}
    </tbody>
  </table>
  <div class="row" style="margin-top:.75rem">
    <button disabled={page === 0} onclick={() => router.setQuery({ page: String(page - 1) })}>← Prev</button>
    <span class="muted small">page {page + 1} / {Math.max(1, Math.ceil(total / limit))}</span>
    <button disabled={(page + 1) * limit >= total} onclick={() => router.setQuery({ page: String(page + 1) })}>Next →</button>
  </div>
</div>

<style>
  th.active { color: var(--text-primary); }
  .x { border: 0; background: transparent; padding: 0 .1rem; color: inherit; }
</style>
