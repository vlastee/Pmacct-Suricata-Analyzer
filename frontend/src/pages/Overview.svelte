<script lang="ts">
  import { api, type Overview } from '../lib/api'
  import { currentRange, router } from '../lib/router.svelte'
  import { fmtBytes, fmtNum, fmtCompact, flag, fmtRate } from '../lib/format'
  import StatTile from '../lib/components/StatTile.svelte'
  import AreaChart from '../lib/components/AreaChart.svelte'
  import BarList from '../lib/components/BarList.svelte'
  import IPLabel from '../lib/components/IPLabel.svelte'
  import Loading from '../lib/components/Loading.svelte'
  import Th from '../lib/components/Th.svelte'
  import { Sorter } from '../lib/sort.svelte'
  const threatSort = new Sorter('malicious')

  let { reloadKey }: { reloadKey: number } = $props()
  let data = $state<Overview | null>(null)
  let error = $state<string | null>(null)
  let loading = $state(false)

  let threats = $derived(data ? threatSort.apply(data.threats, (t, k) => k === 'ip' ? (t.nickname ?? t.ip) : k === 'tags' ? t.tags.join(', ') : k === 'local_hosts' ? t.local_hosts.join(', ') : (t as any)[k]) : [])
  async function load() {
    loading = true; error = null
    try { data = await api.overview(currentRange()) } catch (e: any) { error = e.message } finally { loading = false }
  }
  $effect(() => { void reloadKey; void router.route.query.toString(); load() })

  let spanSec = $derived(data ? (new Date(data.window.until).getTime() - new Date(data.window.since).getTime()) / 1000 : 0)
</script>

<Loading {error} loading={loading && !data} />
{#if data}
  {@const t = data.totals}
  <div class="grid tiles">
    <StatTile label="Total traffic" value={fmtBytes(t.bytes)} sub={fmtRate(t.bytes, spanSec) + ' avg'} />
    <StatTile label="Inbound" value={fmtBytes(t.bytes_in)} sub="external → local" />
    <StatTile label="Outbound" value={fmtBytes(t.bytes_out)} sub="local → external" />
    <StatTile label="Flows" value={fmtCompact(t.flows)} sub={fmtCompact(t.packets) + ' packets'} />
    <StatTile label="Local hosts" value={fmtNum(t.local_hosts)} />
    <StatTile label="External IPs" value={fmtNum(t.external_ips)} sub={data.threats.length ? `${data.threats.length} flagged by VirusTotal` : ''} />
    <a class="tilelink" href={router.href('/alerts')}><StatTile label="Open alerts" value={fmtNum(data.alerts.open + data.alerts.acked)} sub={data.alerts.critical ? `${data.alerts.critical} critical` : (data.alerts.warning ? `${data.alerts.warning} warning` : 'all clear')} /></a>
  </div>

  <div class="card" style="margin-top:1rem">
    <AreaChart points={data.timeseries} interval={data.window.interval_seconds} title="Throughput (per {data.window.interval_seconds >= 3600 ? data.window.interval_seconds / 3600 + 'h' : data.window.interval_seconds / 60 + 'min'} bucket)" />
  </div>

  {#if data.threats.length}
    <div class="card threat" style="margin-top:1rem">
      <h3>⚠ Flagged external IPs in this window</h3>
      <div class="overflow"><table>
        <thead><tr>
          <Th sorter={threatSort} key="ip" label="IP" />
          <Th sorter={threatSort} key="malicious" label="Malicious" num />
          <Th sorter={threatSort} key="suspicious" label="Suspicious" num />
          <Th sorter={threatSort} key="tags" label="Tags" />
          <Th sorter={threatSort} key="local_hosts" label="Talked with" />
          <Th sorter={threatSort} key="bytes" label="Bytes" num />
        </tr></thead>
        <tbody>
          {#each threats as th (th.ip)}
            <tr>
              <td><IPLabel ip={th.ip} nickname={th.nickname} info={th.info} /></td>
              <td class="num">{th.malicious}</td><td class="num">{th.suspicious}</td>
              <td>{th.tags.join(', ')}</td>
              <td>{#each th.local_hosts as h, i}{#if i}, {/if}<a class="mono" href={router.href(`/hosts/${h}`)}>{h}</a>{/each}</td>
              <td class="num">{fmtBytes(th.bytes)}</td>
            </tr>
          {/each}
        </tbody>
      </table></div>
      <a class="small" href={router.href('/threats')}>All threats →</a>
    </div>
  {/if}

  <div class="grid cols-2" style="margin-top:1rem">
    <BarList title="Top local hosts" color="var(--series-1)"
      items={data.top_local.map(h => ({ label: (h.risk && h.risk.critical ? '⛔ ' : h.risk && h.risk.warning ? '⚠ ' : '') + (h.nickname ? `${h.nickname} (${h.ip})` : h.ip), value: h.bytes, href: router.href(`/hosts/${h.ip}`), sub: `↓${fmtBytes(h.bytes_in)} ↑${fmtBytes(h.bytes_out)}` }))} />
    <BarList title="Top external IPs" color="var(--series-2)"
      items={data.top_external.map(h => ({ label: h.nickname ? `${h.nickname} (${h.ip})` : h.ip, value: h.bytes, href: router.href(`/hosts/${h.ip}`),
        sub: [h.info?.country_code ? flag(h.info.country_code) : '', h.info?.hostname ?? h.info?.as_org ?? h.info?.org ?? ''].filter(Boolean).join(' ') }))} />
  </div>
  <div class="grid cols-3" style="margin-top:1rem">
    <BarList title="Protocols" color="var(--series-3)" items={data.protocols.map(p => ({ label: p.name, value: p.bytes, sub: `${fmtCompact(p.flows)} flows` }))} />
    <BarList title="Ports / services" color="var(--series-4)"
      items={data.ports.map(p => ({ label: `${p.port}/${p.name}`, value: p.bytes, sub: p.service, href: router.href('/flows', { port: String(p.port) }) }))} />
    <BarList title="Countries (external traffic)" color="var(--series-7)"
      items={data.countries.map(c => ({ label: `${flag(c.key)} ${c.label}`, value: c.bytes, sub: `${c.ips} IPs`, href: c.key !== '??' ? router.href('/hosts', { scope: 'external', country: c.key }) : undefined }))} />
  </div>
{/if}

<style>
  .threat { border-color: rgba(230,103,103,.5); }
</style>
