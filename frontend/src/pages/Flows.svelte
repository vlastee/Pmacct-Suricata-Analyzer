<script lang="ts">
  import { api, type Flow } from '../lib/api'
  import { currentRange, router } from '../lib/router.svelte'
  import { fmtBytes, fmtNum, fmtTime } from '../lib/format'
  import Loading from '../lib/components/Loading.svelte'
  import IPLabel from '../lib/components/IPLabel.svelte'
  import Th from '../lib/components/Th.svelte'
  import { Sorter } from '../lib/sort.svelte'
  const sorter = new Sorter('stamp_inserted')

  let { reloadKey }: { reloadKey: number } = $props()
  let items = $state<Flow[]>([])
  let error = $state<string | null>(null)
  let loading = $state(false)
  const limit = 200
  let q = $derived(router.route.query)
  let page = $derived(Number(q.get('page') ?? '0'))
  let ip = $state(''), port = $state(''), proto = $state('')
  $effect(() => { ip = q.get('ip') ?? ''; port = q.get('port') ?? ''; proto = q.get('proto') ?? '' })

  let sorted = $derived(sorter.apply(items))
  async function load() {
    loading = true; error = null
    try {
      const r = await api.flows(currentRange(), { ip: q.get('ip') ?? undefined, port: Number(q.get('port') ?? 0) || undefined,
        proto: Number(q.get('proto') ?? 0) || undefined, limit, offset: page * limit })
      items = r.items
    } catch (e: any) { error = e.message } finally { loading = false }
  }
  $effect(() => { void reloadKey; void q.toString(); load() })
  function apply(e: Event) { e.preventDefault(); router.setQuery({ ip: ip || undefined, port: port || undefined, proto: proto || undefined, page: undefined }) }
</script>

<form class="row" style="margin-bottom:1rem" onsubmit={apply}>
  <input placeholder="IP address" bind:value={ip} size="18" />
  <input placeholder="Port" bind:value={port} size="6" />
  <select bind:value={proto}>
    <option value="">any proto</option><option value="6">tcp</option><option value="17">udp</option><option value="1">icmp</option>
  </select>
  <button type="submit" class="primary">Filter</button>
  <button type="button" onclick={() => router.setQuery({ ip: undefined, port: undefined, proto: undefined, page: undefined })}>Clear</button>
</form>

<Loading {error} loading={loading && !items.length} />
<div class="card overflow">
  <table>
    <thead><tr>
      <Th sorter={sorter} key="stamp_inserted" label="Time" />
      <Th sorter={sorter} key="ip_src" label="Source" />
      <Th sorter={sorter} key="port_src" label="Port" num />
      <Th sorter={sorter} key="ip_dst" label="Destination" />
      <Th sorter={sorter} key="port_dst" label="Port" num />
      <Th sorter={sorter} key="proto_name" label="Proto" />
      <Th sorter={sorter} key="packets" label="Packets" num />
      <Th sorter={sorter} key="bytes" label="Bytes" num />
    </tr></thead>
    <tbody>
      {#each sorted as f}
        <tr>
          <td class="small">{fmtTime(f.stamp_inserted)}</td>
          <td><IPLabel ip={f.ip_src} nickname={f.src_nickname} /></td><td class="num mono">{f.port_src}</td>
          <td><IPLabel ip={f.ip_dst} nickname={f.dst_nickname} /></td><td class="num mono">{f.port_dst}</td>
          <td>{f.proto_name}</td><td class="num">{fmtNum(f.packets)}</td><td class="num">{fmtBytes(f.bytes)}</td>
        </tr>
      {:else}<tr><td colspan="8" class="empty">No flows</td></tr>{/each}
    </tbody>
  </table>
  <div class="row" style="margin-top:.75rem">
    <button disabled={page === 0} onclick={() => router.setQuery({ page: String(page - 1) })}>← Prev</button>
    <span class="muted small">page {page + 1} · {items.length} rows (sorting applies to this page)</span>
    <button disabled={items.length < limit} onclick={() => router.setQuery({ page: String(page + 1) })}>Next →</button>
  </div>
</div>
