<script lang="ts">
  import { api, type IDSEvent, type IDSListener, type IDSSignatureStat } from '../lib/api'
  import { currentRange, router } from '../lib/router.svelte'
  import { fmtAgo, fmtCompact, fmtTime } from '../lib/format'
  import IPLabel from '../lib/components/IPLabel.svelte'
  import Loading from '../lib/components/Loading.svelte'
  import Th from '../lib/components/Th.svelte'
  import { Sorter } from '../lib/sort.svelte'

  let { reloadKey }: { reloadKey: number } = $props()
  let events = $state<IDSEvent[]>([])
  let sigs = $state<IDSSignatureStat[]>([])
  let enabled = $state(false)
  let listener = $state<IDSListener | null>(null)
  let lastStored = $state<string | null>(null) // newest Suricata-derived row in the DB; survives restarts
  let error = $state<string | null>(null)
  let loading = $state(false)
  // Expanded row → full event (with raw EVE JSON) fetched on demand; a string is the fetch error.
  let expanded = $state<number | null>(null)
  let full = $state<Record<number, IDSEvent | string>>({})
  // ?event=ID deep link (from an alert): its own card, so it works even outside the list window.
  let focus = $state<IDSEvent | null>(null)
  let focusError = $state<string | null>(null)
  let copied = $state<number | null>(null)
  const sevName: Record<number, string> = { 1: 'high', 2: 'medium', 3: 'low' }
  const sorter = new Sorter('ts')
  let sorted = $derived(sorter.apply(events, (e, k) => (k === 'src' ? e.src_ip : k === 'dst' ? e.dst_ip : (e as any)[k])))

  // Listener health from the snapshot: "quiet" once nothing has arrived for QUIET_MS.
  const QUIET_MS = 10 * 60 * 1000
  let health = $derived.by(() => {
    if (!listener) return null
    if (!listener.last_event) {
      const sinceStart = listener.started ? Date.now() - new Date(listener.started).getTime() : 0
      const tail = lastStored ? ` · last stored event ${fmtAgo(lastStored)}` : ''
      return { level: sinceStart > QUIET_MS ? 'critical' : '', text: (listener.started ? `nothing received since start ${fmtAgo(listener.started)}` : 'nothing received yet') + tail }
    }
    const idle = Date.now() - new Date(listener.last_event).getTime()
    if (idle > QUIET_MS) return { level: 'warning', text: `quiet — last event ${fmtAgo(listener.last_event)}` }
    return { level: 'good', text: `receiving · last event ${fmtAgo(listener.last_event)}` }
  })

  const usedLabel: Record<string, string> = { alerts: 'stored + alerts', names: 'hostnames' }
  const hint: Record<string, string> = {
    alert: 'Stored below and raised as analyzer alerts via the ids rule.',
    'dns.answer': 'A/AAAA answers teach hostnames shown next to IPs across the app.',
    'dns.query': 'Queries carry no answer, so there is nothing to learn from them; usually the bulk of the volume. Harmless.',
    tls: 'TLS SNI teaches hostnames for HTTPS destinations.',
    http: 'HTTP Host headers teach hostnames; long records are the usual truncation victims.',
    flow: 'Ignored — pmacct already provides flows. Untick "flow" in EVE Logged Info to cut syslog volume.',
    stats: 'Ignored — untick "stats" in EVE settings to cut syslog volume.',
    other: 'Types beyond the first 24 distinct ones are folded here.',
  }

  async function load() {
    loading = true; error = null
    try {
      const r = currentRange()
      const q = router.route.query
      const [ev, sm] = await Promise.all([
        api.idsEvents(r, { ip: q.get('ip') ?? undefined, sid: Number(q.get('sid') ?? 0) || undefined, limit: 300 }),
        api.idsSummary(r),
      ])
      events = ev.items; sigs = sm.items; enabled = sm.enabled; listener = sm.listener ?? null; lastStored = sm.last_stored_event ?? null
      const id = Number(q.get('event') ?? 0)
      if (id > 0) {
        if (focus?.id !== id) {
          focus = null; focusError = null
          try { focus = await api.idsEvent(id) } catch (e: any) { focusError = e.message }
        }
      } else { focus = null; focusError = null }
    } catch (e: any) { error = e.message } finally { loading = false }
  }
  $effect(() => { void reloadKey; void router.route.query.toString(); load() })

  async function toggle(id: number) {
    expanded = expanded === id ? null : id
    if (expanded !== null && !full[id]) {
      try { full[id] = await api.idsEvent(id) } catch (e: any) { full[id] = e.message }
    }
  }
  function fullOf(id: number): IDSEvent | null { const f = full[id]; return f && typeof f !== 'string' ? f : null }
  function errOf(id: number): string | null { const f = full[id]; return typeof f === 'string' ? f : null }
  function copy(ev: IDSEvent) {
    navigator.clipboard?.writeText(JSON.stringify(ev.raw ?? ev, null, 2)).catch(() => {})
    copied = ev.id; setTimeout(() => { if (copied === ev.id) copied = null }, 1500)
  }
  function sev(e: IDSEvent) { return e.severity === 1 ? 'critical' : e.severity === 2 ? 'warning' : '' }
</script>

{#if !enabled}
  <div class="card">
    <h3>Suricata IDS not configured</h3>
    <p class="secondary">Set <code>SURICATA_LISTEN</code> (e.g. <code>:5514</code>) and forward Suricata EVE JSON from pfSense over syslog. See the README for the pfSense setup. Alerts, DNS/TLS names and per-host IDS history then appear here and on host pages.</p>
  </div>
{:else}
  {#if listener}
    <div class="row small" style="margin-bottom:1rem">
      {#if health}<span class="badge {health.level}">{health.text}</span>{/if}
      <span class="muted">
        listening on {listener.listen}{#if listener.started}&nbsp;since {fmtTime(listener.started)}{/if}
        · {fmtCompact(listener.received)} events · {fmtCompact(listener.alerts)} alerts · {fmtCompact(listener.names)} names learned
        {#if listener.ignored}· {fmtCompact(listener.ignored)} non-Suricata syslog lines{/if}
        {#if listener.dropped}· <span class="secondary">{fmtCompact(listener.dropped)} dropped (DB errors)</span>{/if}
      </span>
      {#if listener.last_error}
        <span class="badge critical" title={listener.last_error}>last error{#if listener.last_error_at} {fmtAgo(listener.last_error_at)}{/if}: {listener.last_error.slice(0, 80)}</span>
      {/if}
    </div>
    {#if listener.malformed}
      <div class="card warning" style="margin-bottom:1rem">
        <strong>⚠ {fmtCompact(listener.malformed)} malformed / truncated events.</strong>
        <span class="small secondary">Lines arrived that could not be parsed as JSON — almost always the remote syslog transport truncating long EVE records. In pfSense set <em>EVE Log Alert Payload Data Formats = No</em> and log only Alerts + DNS + TLS; if it persists, forward syslog over TCP instead of UDP.</span>
      </div>
    {/if}
  {/if}

  {#if router.route.query.get('event')}
    <div class="card" style="margin-bottom:1rem">
      <h3>IDS event #{router.route.query.get('event')} <button class="x" onclick={() => router.setQuery({ event: undefined })} title="Close">×</button></h3>
      {#if focusError}<span class="badge critical">{focusError}</span>
      {:else if focus}
        <div class="row small meta">
          <span>{fmtTime(focus.ts)}</span>
          {#if focus.src_ip}<IPLabel ip={focus.src_ip} nickname={focus.src_nickname} />{/if}<span>→</span>
          {#if focus.dst_ip}<IPLabel ip={focus.dst_ip} nickname={focus.dst_nickname} />{/if}<span class="mono">:{focus.dst_port ?? '–'}</span>
          <span>{focus.signature ?? '–'}</span>
          <span class="badge {sev(focus)}">{focus.severity ? (sevName[focus.severity] ?? focus.severity) : '–'}</span>
          <button class="small" onclick={() => focus && copy(focus)}>{copied === focus.id ? 'copied' : 'copy JSON'}</button>
        </div>
        <pre>{JSON.stringify(focus.raw, null, 2)}</pre>
      {:else}<span class="small muted">loading…</span>{/if}
    </div>
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
    <div class="card overflow">
      <h3>What arrives <span class="small muted">since listener start</span></h3>
      <table>
        <thead><tr><th>Event type</th><th class="num">Count</th><th class="num">Last</th><th>Used for</th></tr></thead>
        <tbody>
          {#each listener?.types ?? [] as t (t.type)}
            <tr title={hint[t.type] ?? 'Not used by the analyzer'}>
              <td class="mono">{t.type}</td>
              <td class="num">{fmtCompact(t.count)}</td>
              <td class="num small" title={fmtTime(t.last)}>{fmtAgo(t.last)}</td>
              <td class="small">{#if t.used}{usedLabel[t.used] ?? t.used}{:else}<span class="muted">ignored</span>{/if}</td>
            </tr>
          {:else}<tr><td colspan="4" class="empty">Nothing received yet</td></tr>{/each}
        </tbody>
      </table>
      <p class="secondary small" style="margin-top:.75rem">Suricata severity 1 → <b>critical</b>, 2 → <b>warning</b>, 3+ → <b>info</b> analyzer alerts (tunable via the <code>ids</code> rule). Hover a row for what each type does. Counters reset when the analyzer restarts.</p>
    </div>
  </div>

  <div class="card overflow" style="margin-top:1rem">
    <h3>Recent events {#if router.route.query.get('sid')}<span class="badge">sid {router.route.query.get('sid')} <button class="x" onclick={() => router.setQuery({ sid: undefined })}>×</button></span>{/if}</h3>
    <table>
      <thead><tr><th></th>
        <Th {sorter} key="ts" label="Time" /><Th {sorter} key="src" label="Source" /><Th {sorter} key="dst" label="Destination" />
        <Th {sorter} key="dst_port" label="Port" num /><Th {sorter} key="signature" label="Signature" /><Th {sorter} key="severity" label="Sev" num /><Th {sorter} key="app_proto" label="App" />
      </tr></thead>
      <tbody>
        {#each sorted as e (e.id)}
          <tr>
            <td><button class="x" onclick={() => toggle(e.id)} title="Raw EVE record">{expanded === e.id ? '▾' : '▸'}</button></td>
            <td class="small">{fmtTime(e.ts)}</td>
            <td>{#if e.src_ip}<IPLabel ip={e.src_ip} nickname={e.src_nickname} />{:else}–{/if}</td>
            <td>{#if e.dst_ip}<IPLabel ip={e.dst_ip} nickname={e.dst_nickname} />{:else}–{/if}</td>
            <td class="num mono">{e.dst_port ?? '–'}</td>
            <td class="wrap">{e.signature ?? '–'}</td>
            <td class="num"><span class="badge {sev(e)}">{e.severity ? (sevName[e.severity] ?? e.severity) : '–'}</span></td>
            <td class="small">{e.app_proto ?? '–'}</td>
          </tr>
          {#if expanded === e.id}
            <tr class="detail"><td colspan="8">
              {#if errOf(e.id)}<span class="badge critical">{errOf(e.id)}</span>
              {:else if fullOf(e.id)}
                <div class="row small muted meta">
                  <span>event #{e.id} · {e.category ?? '–'} · action {e.action ?? '–'} · {(e.proto ?? '').toUpperCase()}</span>
                  <button class="small" onclick={() => { const f = fullOf(e.id); if (f) copy(f) }}>{copied === e.id ? 'copied' : 'copy JSON'}</button>
                  {#if e.src_ip}<a href={router.href(`/hosts/${e.src_ip}`)}>source host →</a>{/if}
                  {#if e.dst_ip}<a href={router.href(`/hosts/${e.dst_ip}`)}>destination host →</a>{/if}
                  <a href={router.href('/alerts', { rule: 'ids' })}>IDS alerts →</a>
                </div>
                <pre>{JSON.stringify(fullOf(e.id)?.raw, null, 2)}</pre>
              {:else}<span class="small muted">loading…</span>{/if}
            </td></tr>
          {/if}
        {:else}<tr><td colspan="8" class="empty">No events</td></tr>{/each}
      </tbody>
    </table>
  </div>
{/if}

<style>
  .wrap { white-space: normal; min-width: 240px; }
  .x { border: 0; background: transparent; color: inherit; padding: 0 .2rem; cursor: pointer; }
  tr.detail td { background: var(--surface-2); }
  pre { margin: 0; font-size: .8rem; white-space: pre-wrap; color: var(--text-secondary); max-height: 320px; overflow: auto; }
  .meta { margin-bottom: .4rem; }
</style>
