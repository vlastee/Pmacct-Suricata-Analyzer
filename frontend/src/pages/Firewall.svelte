<script lang="ts">
  import { api, type FirewallEvent, type FirewallSummary, type FirewallIngest, type FirewallTop } from '../lib/api'
  import { currentRange, router } from '../lib/router.svelte'
  import { fmtAgo, fmtCompact, fmtTime } from '../lib/format'
  import { auth } from '../lib/auth.svelte'
  import IPLabel from '../lib/components/IPLabel.svelte'
  import Loading from '../lib/components/Loading.svelte'
  import StatTile from '../lib/components/StatTile.svelte'

  let { reloadKey }: { reloadKey: number } = $props()
  let sum = $state<FirewallSummary | null>(null)
  let events = $state<FirewallEvent[]>([])
  let enabled = $state(true)
  let retention = $state(0)
  let ingest = $state<FirewallIngest | null>(null)
  let error = $state<string | null>(null)
  let loading = $state(false)
  let canEdit = $derived(!!auth.user?.is_admin || auth.authDisabled)

  const FILTERS = ['ip', 'action', 'iface', 'port', 'tracker', 'attempts'] as const
  let q = $derived(router.route.query)
  let filter = $derived(Object.fromEntries(FILTERS.map(k => [k, q.get(k) ?? undefined])) as Record<string, string | undefined>)
  let active = $derived(FILTERS.filter(k => filter[k]))
  let ipInput = $state('')
  let portInput = $state('')
  $effect(() => { ipInput = filter.ip ?? ''; portInput = filter.port ?? '' })

  async function load() {
    loading = true; error = null
    try {
      const r = currentRange()
      const [s, e] = await Promise.all([api.firewallSummary(r, { ...filter, limit: 10 }), api.firewallEvents(r, { ...filter, limit: 300 })])
      sum = s.summary; enabled = s.enabled; retention = s.retention_days; ingest = s.ingest ?? null; events = e.items
    } catch (e: any) { error = e.message } finally { loading = false }
  }
  $effect(() => { void reloadKey; void router.route.query.toString(); load() })

  function set(k: string, v: string | undefined) { router.setQuery({ [k]: v || undefined }) }
  function applyInputs(ev: Event) { ev.preventDefault(); router.setQuery({ ip: ipInput.trim() || undefined, port: portInput.trim() || undefined }) }

  // Rule naming / expected flag, edited inline in the rules table.
  let editing = $state<string | null>(null)
  let draft = $state('')
  let saveErr = $state<string | null>(null)
  async function saveRule(r: FirewallTop, patch: { label?: string; expected?: boolean }) {
    saveErr = null
    try {
      await api.setFirewallRule(r.key, { label: patch.label ?? r.label ?? '', expected: patch.expected ?? !!r.expected })
      editing = null
      await load()
    } catch (e: any) { saveErr = e.message }
  }

  // Timeline: stacked bars, blocked (series-2) over passed (series-1).
  let maxBar = $derived(Math.max(1, ...(sum?.series ?? []).map(p => p.blocked + p.passed)))
  function ruleName(r: { key?: string; tracker?: number; label?: string }) {
    const t = r.key ?? (r.tracker != null ? String(r.tracker) : '')
    return r.label ? r.label : t ? `tracker ${t}` : 'no tracker'
  }
</script>

{#if !enabled}
  <div class="card">
    <h3>Firewall log not ingested</h3>
    <p class="small secondary">Set <code>SURICATA_LISTEN</code> (e.g. <code>:5514</code>) and leave <code>FIREWALL_INGEST</code> on, then point pfSense remote logging (Status → System Logs → Settings, contents "Everything") at this host.</p>
  </div>
{:else}
  <div class="row small" style="margin-bottom:1rem; flex-wrap:wrap; gap:.5rem">
    <form class="row" style="gap:.4rem" onsubmit={applyInputs}>
      <input placeholder="IP (either side)" bind:value={ipInput} style="width:11rem" />
      <input placeholder="dst port" bind:value={portInput} style="width:6rem" />
      <button type="submit">Filter</button>
    </form>
    <select value={filter.action ?? ''} onchange={(e) => set('action', (e.target as HTMLSelectElement).value)}>
      <option value="">pass + block</option><option value="block">block</option><option value="pass">pass</option><option value="reject">reject</option>
    </select>
    <label class="row" style="gap:.3rem" title="Only new connection attempts: non-TCP, or TCP SYN without ACK. Hides stray packets of finished connections.">
      <input type="checkbox" checked={!!filter.attempts} onchange={(e) => set('attempts', (e.target as HTMLInputElement).checked ? '1' : undefined)} /> new connections only
    </label>
    {#each active as k}
      <span class="badge">{k}: {filter[k]} <button class="x" onclick={() => set(k, undefined)} title="Remove filter">×</button></span>
    {/each}
    <span class="spacer"></span>
    <span class="muted">
      {#if ingest}{fmtCompact(ingest.stored)} stored since restart{#if ingest.last_event} · last {fmtAgo(ingest.last_event)}{/if} · {/if}
      kept {retention ? retention + ' days' : 'forever'}{#if sum?.oldest} · oldest {fmtTime(sum.oldest)}{/if}
    </span>
  </div>

  {#if error}<div class="card"><span class="badge critical">{error}</span></div>{/if}
  {#if loading && !sum}<Loading />{/if}

  {#if sum}
    <div class="grid tiles" style="margin-bottom:1rem">
      <StatTile label="Records" value={fmtCompact(sum.total)} sub="logged by pfSense" />
      <StatTile label="Blocked" value={fmtCompact(sum.blocked)} sub={`${fmtCompact(sum.attempts)} new connection attempts`} />
      <StatTile label="Passed (logged)" value={fmtCompact(sum.passed)} sub="only rules with logging on" />
      <StatTile label="Local hosts blocked" value={fmtCompact(sum.local_blocked)} sub="outbound attempts dropped" />
    </div>

    {#if sum.series.length > 1}
      <div class="card" style="margin-bottom:1rem">
        <h3>Timeline <span class="small muted">blocked <span class="sw" style="background:var(--series-2)"></span> passed <span class="sw" style="background:var(--series-1)"></span></span></h3>
        <svg class="bars" viewBox="0 0 {sum.series.length * 10} 100" preserveAspectRatio="none" role="img" aria-label="Firewall records over time">
          {#each sum.series as p, i}
            {@const hb = (p.blocked / maxBar) * 100}
            {@const hp = (p.passed / maxBar) * 100}
            <rect x={i * 10 + 1} y={100 - hb - hp} width="8" height={hp} fill="var(--series-1)"><title>{fmtTime(p.t)} · {p.passed} passed</title></rect>
            <rect x={i * 10 + 1} y={100 - hb} width="8" height={hb} fill="var(--series-2)"><title>{fmtTime(p.t)} · {p.blocked} blocked</title></rect>
          {/each}
        </svg>
        <div class="row small muted"><span>{fmtTime(sum.series[0].t)}</span><span class="spacer"></span><span>{fmtTime(sum.series[sum.series.length - 1].t)}</span><span class="muted">&nbsp;· peak {fmtCompact(maxBar)}/bucket</span></div>
      </div>
    {/if}

    <div class="grid cols-2" style="margin-bottom:1rem">
      {#each [{ t: 'Top sources', rows: sum.sources }, { t: 'Top destinations', rows: sum.destinations }] as tbl}
        <div class="card">
          <h3>{tbl.t}</h3>
          {#if !tbl.rows.length}<div class="empty">No records</div>{:else}
            <table>
              <thead><tr><th>Address</th><th class="num">Records</th><th class="num" title="New connection attempts">Attempts</th><th class="num">Peers</th><th>Last</th></tr></thead>
              <tbody>
                {#each tbl.rows as r}
                  <tr>
                    <td><IPLabel ip={r.key} nickname={r.nickname ?? null} /> <button class="link small" onclick={() => set('ip', r.key)} title="Filter on this address">filter</button></td>
                    <td class="num mono">{fmtCompact(r.packets)}</td><td class="num mono">{fmtCompact(r.attempts)}</td><td class="num mono">{r.peers}</td>
                    <td class="small muted">{fmtAgo(r.last)}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/if}
        </div>
      {/each}
    </div>

    <div class="grid wide-left" style="margin-bottom:1rem">
      <div class="card">
        <h3>Rules <span class="small muted">name pfSense trackers; mark intended blocks as expected so they never raise alerts</span></h3>
        {#if saveErr}<span class="badge critical">{saveErr}</span>{/if}
        {#if !sum.rules.length}<div class="empty">No records</div>{:else}
          <table>
            <thead><tr><th>Rule</th><th>Interface</th><th>Action</th><th class="num">Records</th><th class="num">Attempts</th><th class="num">Sources</th><th title="Blocks by expected rules don't raise alerts">Expected</th></tr></thead>
            <tbody>
              {#each sum.rules as r}
                <tr>
                  <td>
                    {#if editing === r.key}
                      <form class="row" style="gap:.3rem" onsubmit={(e) => { e.preventDefault(); saveRule(r, { label: draft }) }}>
                        <input bind:value={draft} placeholder="e.g. Block telemetry" style="width:12rem" /><button type="submit">Save</button><button type="button" onclick={() => (editing = null)}>Cancel</button>
                      </form>
                    {:else}
                      <button class="link" onclick={() => set('tracker', r.key || undefined)} title="Filter on this rule">{ruleName(r)}</button>
                      {#if r.label && r.key}<span class="small muted mono">{r.key}</span>{/if}
                      {#if canEdit && r.key}<button class="link small" onclick={() => { editing = r.key; draft = r.label ?? '' }}>rename</button>{/if}
                    {/if}
                  </td>
                  <td class="mono small">{r.iface || '–'}</td>
                  <td><span class="badge {r.action === 'pass' ? 'good' : 'warning'}">{r.action}</span></td>
                  <td class="num mono">{fmtCompact(r.packets)}</td><td class="num mono">{fmtCompact(r.attempts)}</td><td class="num mono">{r.peers}</td>
                  <td>{#if r.key}<input type="checkbox" checked={!!r.expected} disabled={!canEdit} onchange={(e) => saveRule(r, { expected: (e.target as HTMLInputElement).checked })} />{/if}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </div>
      <div class="card">
        <h3>Top destination ports</h3>
        {#if !sum.ports.length}<div class="empty">No records</div>{:else}
          <table>
            <thead><tr><th>Port</th><th class="num">Records</th><th class="num">Attempts</th><th class="num">Sources</th></tr></thead>
            <tbody>
              {#each sum.ports as r}
                <tr>
                  <td><button class="link mono" onclick={() => set('port', r.key.split('/')[1])}>{r.key}</button></td>
                  <td class="num mono">{fmtCompact(r.packets)}</td><td class="num mono">{fmtCompact(r.attempts)}</td><td class="num mono">{r.peers}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </div>
    </div>

    <div class="card">
      <h3>Records <span class="small muted">newest {events.length}</span></h3>
      {#if !events.length}<div class="empty">No records in this window{#if active.length} for these filters{/if}.</div>{:else}
        <table>
          <thead><tr><th>Time</th><th>Action</th><th>If / dir</th><th>Rule</th><th>Source</th><th>Destination</th><th>Proto</th><th>Flags</th></tr></thead>
          <tbody>
            {#each events as e}
              <tr class:dim={!e.attempt}>
                <td class="small nowrap">{fmtTime(e.ts)}</td>
                <td><span class="badge {e.action === 'pass' ? 'good' : 'warning'}">{e.action}</span></td>
                <td class="mono small">{e.iface ?? '–'} {e.direction ?? ''}</td>
                <td class="small">{ruleName(e)}</td>
                <td class="mono small">{#if e.src}<IPLabel ip={e.src} nickname={e.src_nickname ?? null} />{e.src_port != null ? ':' + e.src_port : ''}{:else}–{/if}</td>
                <td class="mono small">{#if e.dst}<IPLabel ip={e.dst} nickname={e.dst_nickname ?? null} />{e.dst_port != null ? ':' + e.dst_port : ''}{:else}–{/if}</td>
                <td class="mono small">{e.proto ?? '–'}</td>
                <td class="mono small" title={e.attempt ? 'new connection attempt' : 'stray packet of a finished connection'}>{e.tcp_flags ?? e.icmp_type ?? ''}</td>
              </tr>
            {/each}
          </tbody>
        </table>
        <div class="small muted" style="margin-top:.5rem">Greyed rows are stray packets of finished connections (FIN/RST/ACK after pfSense dropped the state), not new attempts.</div>
      {/if}
    </div>
  {/if}
{/if}

<style>
  .bars { width: 100%; height: 120px; display: block; }
  .sw { display: inline-block; width: .7rem; height: .7rem; border-radius: 2px; vertical-align: middle; margin: 0 .3rem 0 .1rem; }
  tr.dim td { opacity: .55; }
  .nowrap { white-space: nowrap; }
  button.link { background: none; border: none; padding: 0; color: var(--link, var(--series-1)); cursor: pointer; }
  button.x { background: none; border: none; padding: 0 0 0 .2rem; cursor: pointer; color: inherit; }
</style>
