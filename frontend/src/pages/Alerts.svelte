<script lang="ts">
  import { api, type Alert, type AlertRetention } from '../lib/api'
  import { router } from '../lib/router.svelte'
  import { exclusions } from '../lib/exclusions.svelte'
  import { fmtAgo, fmtTime } from '../lib/format'
  import Severity from '../lib/components/Severity.svelte'
  import IPLabel from '../lib/components/IPLabel.svelte'
  import Loading from '../lib/components/Loading.svelte'

  let { reloadKey }: { reloadKey: number } = $props()
  let items = $state<Alert[]>([])
  let total = $state(0)
  let error = $state<string | null>(null)
  let loading = $state(false)
  let expanded = $state<number | null>(null)

  let q = $derived(router.route.query)
  let view = $derived(q.get('state') ?? 'active')
  let severity = $derived(q.get('severity') ?? '')
  let rule = $derived(q.get('rule') ?? '')

  async function load() {
    loading = true; error = null
    try {
      const r = await api.alerts({ state: view, severity: severity || undefined, rule: rule || undefined, host: q.get('host') ?? undefined, limit: 200 })
      items = r.items; total = r.total
    } catch (e: any) { error = e.message } finally { loading = false }
  }
  $effect(() => { void reloadKey; void q.toString(); load() })

  async function trustToggle(ip: string, current?: string) {
    try {
      if (current) {
        const e = exclusions.items.find(x => x.pattern === current)
        if (!e) return
        if (e.kind !== 'ip' && !confirm(`Remove "${e.pattern}" from the trusted list?`)) return
        await exclusions.remove(e.id)
      } else {
        await exclusions.add(ip)
      }
      await load()
    } catch (e: any) { error = e.message }
  }
  async function act(a: Alert, action: 'ack' | 'resolve' | 'reopen') {
    try { await api.alertAction(a.id, action); await load() } catch (e: any) { error = e.message }
  }
  function filterText() {
    const parts = []
    if (rule) parts.push(`rule ${rule}`)
    if (q.get('host')) parts.push(`host ${q.get('host')}`)
    if (severity) parts.push(`severity ${severity}`)
    return parts.length ? ` matching ${parts.join(', ')}` : ''
  }
  async function deleteResolved() {
    if (!confirm(`Permanently delete all resolved alerts${filterText()}? This cannot be undone.`)) return
    try {
      const r = await api.deleteResolvedAlerts({ rule: rule || undefined, host: q.get('host') ?? undefined, severity: severity || undefined })
      notice = `deleted ${r.deleted} resolved alert${r.deleted === 1 ? '' : 's'}`
      await load()
    } catch (e: any) { error = e.message }
  }
  async function deleteOne(a: Alert) {
    if (!confirm(`Permanently delete this resolved alert?\n${a.title}`)) return
    try { await api.deleteAlert(a.id); await load() } catch (e: any) { error = e.message }
  }
  let notice = $state('')
  // retention settings
  let showRetention = $state(false)
  let retention = $state<AlertRetention | null>(null)
  let retMsg = $state('')
  async function loadRetention() { try { retention = await api.alertSettings() } catch (e: any) { retMsg = e.message } }
  $effect(() => { if (showRetention && !retention) loadRetention() })
  async function saveRetention() {
    if (!retention) return
    retMsg = 'saving…'
    try {
      const r = await api.setAlertSettings(retention)
      retention = r.settings
      const del = Object.entries(r.deleted).map(([s, n]) => `${n} ${s}`).join(', ')
      retMsg = del ? `saved · deleted ${del}` : 'saved'
      await load()
    } catch (e: any) { retMsg = e.message }
  }
  async function resolveRule() {
    if (!rule) return
    if (!confirm(`Resolve all active "${rule}" alerts?`)) return
    try { await api.resolveAlerts({ rule }); await load() } catch (e: any) { error = e.message }
  }
</script>

<div class="row" style="margin-bottom:1rem">
  <div class="seg">
    {#each [['active', 'Active'], ['open', 'Open'], ['acked', 'Acked'], ['resolved', 'Resolved'], ['all', 'All']] as [k, l]}
      <button class:active={view === k} onclick={() => router.setQuery({ state: k })}>{l}</button>
    {/each}
  </div>
  <select value={severity} onchange={(e) => router.setQuery({ severity: e.currentTarget.value || undefined })}>
    <option value="">any severity</option><option value="critical">critical</option><option value="warning">warning</option><option value="info">info</option>
  </select>
  {#if rule}<span class="badge">rule: {rule} <button class="x" onclick={() => router.setQuery({ rule: undefined })}>×</button></span>
    <button class="small" onclick={resolveRule}>Resolve all</button>{/if}
  {#if q.get('host')}<span class="badge">host: {q.get('host')} <button class="x" onclick={() => router.setQuery({ host: undefined })}>×</button></span>{/if}
  <span class="spacer"></span>
  {#if notice}<span class="small muted">{notice}</span>{/if}
  {#if view === 'resolved' || view === 'all'}
    <button class="small" onclick={deleteResolved} title="Permanently delete resolved alerts (honours the rule / host / severity filters)">Delete resolved{filterText() ? '…' : ''}</button>
  {/if}
  <span class="muted small">{total} alert{total === 1 ? '' : 's'}</span>
  <button class="small" onclick={() => (showRetention = !showRetention)} title="Auto-resolve and deletion timing">⚙ retention</button>
</div>
{#if showRetention}
  <div class="card" style="margin-bottom:1rem">
    <h3>Alert retention</h3>
    {#if retention}
      <div class="row small" style="gap:1rem; flex-wrap:wrap">
        <label class="row" style="gap:.3rem">auto-resolve open alerts idle for
          <input type="number" min="1" max="365" bind:value={retention.auto_resolve_days} style="width:4.5rem" /> days</label>
        <span class="muted">·</span>
        <span>delete resolved after</span>
        {#each ['info', 'warning', 'critical'] as sev (sev)}
          <label class="row" style="gap:.3rem"><span class="badge {sev === 'info' ? '' : sev}">{sev}</span>
            <input type="number" min="0" max="3650" bind:value={retention.delete_resolved_days[sev]} style="width:4.5rem" /> days</label>
        {/each}
        <span class="muted">(0 = keep forever)</span>
        <button class="primary small" onclick={saveRetention}>Save</button>
        {#if retMsg}<span class="muted">{retMsg}</span>{/if}
      </div>
      <p class="small muted" style="margin:.5rem 0 0">Open and acked alerts are never deleted automatically; they resolve after the idle period, then the per-severity timer starts. Saving applies the deletion immediately and daily thereafter.</p>
    {:else}<span class="small muted">{retMsg || 'loading…'}</span>{/if}
  </div>
{/if}

<Loading {error} loading={loading && !items.length} />
<div class="card overflow">
  <table>
    <thead><tr><th></th><th>Severity</th><th>Rule</th><th>What</th><th>Host</th><th>Peer</th><th class="num">Seen</th><th class="num">Last</th><th></th></tr></thead>
    <tbody>
      {#each items as a (a.id)}
        <tr class:crit={a.severity === 'critical'}>
          <td><button class="x" onclick={() => (expanded = expanded === a.id ? null : a.id)} title="Details">{expanded === a.id ? '▾' : '▸'}</button></td>
          <td><Severity sev={a.severity} /></td>
          <td><a href={router.href('/rules', { open: a.rule })} class="mono small">{a.rule}</a></td>
          <td class="wrap">{a.title}</td>
          <td>{#if a.host}<IPLabel ip={a.host} nickname={a.host_nickname} local={true} />{:else}–{/if}</td>
          <td>{#if a.peer}<IPLabel ip={a.peer} nickname={a.peer_nickname} />{:else}–{/if}</td>
          <td class="num">{a.count}</td>
          <td class="num small" title={fmtTime(a.last_seen)}>{fmtAgo(a.last_seen)}</td>
          <td class="num actions">
            {#if a.state === 'open'}<button class="small" onclick={() => act(a, 'ack')}>Ack</button>{/if}
            {#if a.state === 'acked'}<button class="small" onclick={() => act(a, 'reopen')}>Reopen</button>{/if}
            {#if a.state !== 'resolved'}<button class="small" onclick={() => act(a, 'resolve')}>Resolve</button>
            {:else}<span class="badge good">resolved</span> <button class="small" onclick={() => act(a, 'reopen')} title="Move back to open">Reopen</button> <button class="small" onclick={() => deleteOne(a)} title="Permanently delete">Delete</button>{/if}
          </td>
        </tr>
        {#if expanded === a.id}
          <tr class="detail"><td colspan="9">
            <pre>{JSON.stringify(a.details, null, 2)}</pre>
            <div class="small muted">first seen {fmtTime(a.first_seen)} · state {a.state}{#if a.notified_at} · notified {fmtAgo(a.notified_at)}{/if}
              {#if a.host} · <a href={router.href(`/hosts/${a.host}`)}>host page →</a>{/if}
              {#if a.peer} · <a href={router.href(`/hosts/${a.peer}`)}>peer page →</a>{/if}
              {#if a.details?.ids_event_id} · <a href={router.href('/ids', { event: String(a.details.ids_event_id) })}>IDS event →</a>{/if}</div>
            <div class="row small" style="margin-top:.4rem; gap:.4rem">
              <span class="muted">trusted list:</span>
              {#if a.host}<button class="small" onclick={() => trustToggle(a.host!, a.host_excluded)}>{a.host_excluded ? `include ${a.host} (now excluded by ${a.host_excluded})` : `exclude host ${a.host}`}</button>{/if}
              {#if a.peer}<button class="small" onclick={() => trustToggle(a.peer!, a.peer_excluded)}>{a.peer_excluded ? `include ${a.peer} (now excluded by ${a.peer_excluded})` : `exclude peer ${a.peer}`}</button>{/if}
              <span class="muted">excluding an address resolves its open alerts and stops every rule alerting on it</span>
            </div>
          </td></tr>
        {/if}
      {:else}
        <tr><td colspan="9" class="empty">No alerts {view === 'active' ? '— all clear 🎉' : ''}</td></tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  tr.crit td { background: rgba(230,103,103,.06); }
  .wrap { white-space: normal; min-width: 280px; }
  .actions button { margin-left: .25rem; }
  .x { border: 0; background: transparent; color: inherit; padding: 0 .2rem; cursor: pointer; }
  tr.detail td { background: var(--surface-2); }
  pre { margin: 0 0 .4rem; font-size: .8rem; white-space: pre-wrap; color: var(--text-secondary); max-height: 240px; overflow: auto; }
</style>
