<script lang="ts">
  import { api, type IDSEvent, type IDSSignatureStat } from '../lib/api'
  import { currentRange, router } from '../lib/router.svelte'
  import { fmtTime, fmtCompact } from '../lib/format'
  import IPLabel from '../lib/components/IPLabel.svelte'
  import Loading from '../lib/components/Loading.svelte'
  import Th from '../lib/components/Th.svelte'
  import { Sorter } from '../lib/sort.svelte'

  let { reloadKey }: { reloadKey: number } = $props()
  let events = $state<IDSEvent[]>([])
  let sigs = $state<IDSSignatureStat[]>([])
  let enabled = $state(false)
  let listener = $state<any>(null)
  let error = $state<string | null>(null)
  let loading = $state(false)
  const sevName: Record<number, string> = { 1: 'high', 2: 'medium', 3: 'low' }
  const sorter = new Sorter('ts')
  let sorted = $derived(sorter.apply(events, (e, k) => (k === 'src' ? e.src_ip : k === 'dst' ? e.dst_ip : (e as any)[k])))

  async function load() {
    loading = true; error = null
    try {
      const r = currentRange()
      const [ev, sm] = await Promise.all([
        api.idsEvents(r, { ip: router.route.query.get('ip') ?? undefined, sid: Number(router.route.query.get('sid') ?? 0) || undefined, limit: 300 }),
        api.idsSummary(r),
      ])
      events = ev.items; sigs = sm.items; enabled = sm.enabled; listener = sm.listener
    } catch (e: any) { error = e.message } finally { loading = false }
  }
  $effect(() => { void reloadKey; void router.route.query.toString(); load() })
</script>

{#if !enabled}
  <div class="card">
    <h3>Suricata IDS not configured</h3>
    <p class="secondary">Set <code>SURICATA_LISTEN</code> (e.g. <code>:5514</code>) and forward Suricata EVE JSON from pfSense over syslog. See the README for the pfSense setup. Alerts, DNS/TLS names and per-host IDS history then appear here and on host pages.</p>
  </div>
{:else}
  {#if listener}
    <div class="row small muted" style="margin-bottom:1rem">
      listening on {listener.listen} · {fmtCompact(listener.received)} events · {fmtCompact(listener.alerts)} alerts · {fmtCompact(listener.names)} names learned
      {#if listener.last_event}· last {fmtTime(listener.last_event)}{/if}{#if listener.dropped}· <span class="secondary">{listener.dropped} dropped</span>{/if}
    </div>
    {#if listener.malformed}
      <div class="card" style="border-color: rgba(201,133,0,.5); margin-bottom:1rem">
        <strong>⚠ {fmtCompact(listener.malformed)} malformed / truncated events.</strong>
        <span class="small secondary">Lines arrived that could not be parsed as JSON — almost always the remote syslog transport truncating long EVE records. In pfSense set <em>EVE Log Alert Payload Data Formats = No</em> and log only Alerts + DNS + TLS; if it persists, forward syslog over TCP instead of UDP.</span>
      </div>
    {/if}
  {/if}
  <Loading {error} loading={loading && !events.length} />
  <div class="grid cols-2">
    <div class="card overflow">
      <h3>Signatures</h3>
      <table>
        <thead><tr><th>Signature</th><th>Category</th><th class="num">Sev</th><th class="num">Count</th><th class="num">Sources</th></tr></thead>
        <tbody>
          {#each sigs as s (s.sid)}
            <tr><td class="wrap"><a href={router.href('/ids', { sid: String(s.sid) })}>{s.signature}</a></td>
              <td class="small">{s.category ?? '–'}</td><td class="num">{s.severity ?? '–'}</td>
              <td class="num">{fmtCompact(s.count)}</td><td class="num">{s.sources}</td></tr>
          {:else}<tr><td colspan="5" class="empty">No IDS alerts in this window</td></tr>{/each}
        </tbody>
      </table>
    </div>
    <div class="card">
      <h3>How it maps</h3>
      <p class="secondary small">Suricata severity 1 → <b>critical</b>, 2 → <b>warning</b>, 3+ → <b>info</b> analyzer alerts (tunable via the <code>ids</code> rule). Every event is stored here; DNS answers and TLS SNI teach hostnames shown across the app.</p>
    </div>
  </div>

  <div class="card overflow" style="margin-top:1rem">
    <h3>Recent events {#if router.route.query.get('sid')}<span class="badge">sid {router.route.query.get('sid')} <button class="x" onclick={() => router.setQuery({ sid: undefined })}>×</button></span>{/if}</h3>
    <table>
      <thead><tr>
        <Th {sorter} key="ts" label="Time" /><Th {sorter} key="src" label="Source" /><Th {sorter} key="dst" label="Destination" />
        <Th {sorter} key="dst_port" label="Port" num /><Th {sorter} key="signature" label="Signature" /><Th {sorter} key="severity" label="Sev" num /><Th {sorter} key="app_proto" label="App" />
      </tr></thead>
      <tbody>
        {#each sorted as e (e.id)}
          <tr>
            <td class="small">{fmtTime(e.ts)}</td>
            <td>{#if e.src_ip}<IPLabel ip={e.src_ip} nickname={e.src_nickname} />{:else}–{/if}</td>
            <td>{#if e.dst_ip}<IPLabel ip={e.dst_ip} nickname={e.dst_nickname} />{:else}–{/if}</td>
            <td class="num mono">{e.dst_port ?? '–'}</td>
            <td class="wrap">{e.signature ?? '–'}</td>
            <td class="num"><span class="badge {e.severity === 1 ? 'critical' : e.severity === 2 ? 'warning' : ''}">{e.severity ? (sevName[e.severity] ?? e.severity) : '–'}</span></td>
            <td class="small">{e.app_proto ?? '–'}</td>
          </tr>
        {:else}<tr><td colspan="7" class="empty">No events</td></tr>{/each}
      </tbody>
    </table>
  </div>
{/if}

<style>
  .wrap { white-space: normal; min-width: 240px; }
  .x { border: 0; background: transparent; color: inherit; cursor: pointer; }
</style>
