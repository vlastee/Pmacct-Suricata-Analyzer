<script lang="ts">
  import { api, type HostDetail, type IPInfo } from '../lib/api'
  import { currentRange, router } from '../lib/router.svelte'
  import { fmtBytes, fmtCompact, fmtTime, flag, fmtAgo } from '../lib/format'
  import AreaChart from '../lib/components/AreaChart.svelte'
  import StatTile from '../lib/components/StatTile.svelte'
  import IPLabel from '../lib/components/IPLabel.svelte'
  import Loading from '../lib/components/Loading.svelte'
  import Th from '../lib/components/Th.svelte'
  import { Sorter } from '../lib/sort.svelte'
  import { exclusions } from '../lib/exclusions.svelte'
  const peerSort = new Sorter('bytes')
  const portSort = new Sorter('bytes')

  let { ip, reloadKey }: { ip: string; reloadKey: number } = $props()
  let data = $state<HostDetail | null>(null)
  let error = $state<string | null>(null)
  let loading = $state(false)
  let refreshing = $state(false)
  let refreshMsg = $state('')

  let peers = $derived(data ? peerSort.apply(data.peers, (p, k) => k === 'peer' ? (p.nickname ?? p.ip) : k === 'org' ? (p.info?.hostname ?? p.info?.org ?? p.info?.as_org) : (p as any)[k]) : [])
  let ports = $derived(data ? portSort.apply(data.ports, (p, k) => k === 'port' ? p.port * 1000 + p.proto : (p as any)[k]) : [])
  async function load() {
    loading = true; error = null
    try { data = await api.host(ip, currentRange()) } catch (e: any) { error = e.message } finally { loading = false }
  }
  $effect(() => { void reloadKey; void ip; void router.route.query.toString(); load() })

  async function refresh() {
    refreshing = true; refreshMsg = ''
    try {
      const info: IPInfo = await api.refreshIP(ip)
      if (data) data.host.info = info
      refreshMsg = info.status === 'ok' ? 'updated' : `lookup failed: ${info.error}`
    } catch (e: any) { refreshMsg = e.message } finally { refreshing = false }
  }
  let info = $derived(data?.host.info ?? null)
  let vt = $derived(info?.vt ?? null)

  // trusted list (alert exclusions)
  let exclMsg = $state('')
  let serverMatch = $state<{ excluded: boolean; pattern: string } | null>(null)
  $effect(() => { void ip; void exclusions.items; api.exclusionMatch(ip).then(m => (serverMatch = m)).catch(() => (serverMatch = null)) })
  let trustedBy = $derived(serverMatch?.excluded ? serverMatch.pattern : exclusions.matchIP(ip)?.pattern ?? null)
  async function trust(pattern: string) {
    exclMsg = ''
    try {
      const r = await exclusions.add(pattern)
      exclMsg = r.resolved ? `excluded · ${r.resolved} open alert${r.resolved === 1 ? '' : 's'} resolved` : 'excluded from alerts'
      load()
    } catch (e: any) { exclMsg = e.message }
  }
  async function untrust() {
    const pat = trustedBy
    const e = exclusions.items.find(x => x.pattern === pat)
    if (!e) { exclMsg = 'covered by a pattern not in the list?'; return }
    if (e.kind !== 'ip' && !confirm(`Remove the pattern "${e.pattern}" from the trusted list? It may cover other addresses too.`)) return
    exclMsg = ''
    try { await exclusions.remove(e.id); exclMsg = 'alerts enabled again' } catch (err: any) { exclMsg = err.message }
  }
  // Name-based suggestions: exact names and their parent-domain wildcards.
  let nameSuggestions = $derived.by(() => {
    const names = new Set<string>()
    for (const n of [info?.hostname, ...(info?.names?.map(x => x.name) ?? []), ...(data?.host.names ?? [])]) if (n) names.add(n.replace(/\.$/, '').toLowerCase())
    const out: string[] = []
    for (const n of [...names].slice(0, 4)) {
      out.push(n)
      const parts = n.split('.')
      if (parts.length > 2) out.push('*.' + parts.slice(-2).join('.'))
    }
    return [...new Set(out)].filter(p => !exclusions.items.some(e => e.pattern === p)).slice(0, 6)
  })
  // nickname editor
  let editing = $state(false)
  let nickInput = $state('')
  let noteInput = $state('')
  let kindInput = $state('other')
  let nickMsg = $state('')
  const kinds = ['pc', 'phone', 'server', 'iot', 'network', 'other']
  async function startEdit() {
    nickInput = data?.host.nickname ?? ''
    noteInput = ''
    kindInput = data?.kind ?? 'other'
    try { const n = await api.nicknames(ip); const m = n.items.find(x => x.ip === ip); if (m) { nickInput = m.nickname; noteInput = m.note ?? ''; kindInput = m.kind } } catch {}
    editing = true
  }
  async function saveNick(e: Event) {
    e.preventDefault(); nickMsg = ''
    try {
      if (nickInput.trim()) {
        const n = await api.setNickname(ip, nickInput.trim(), noteInput.trim() || null, kindInput)
        if (data) { data.host.nickname = n.nickname; data.kind = n.kind }
      } else if (data?.host.nickname) {
        await api.deleteNickname(ip)
        data.host.nickname = null
      }
      editing = false
    } catch (err: any) { nickMsg = err.message }
  }
</script>

<div class="row" style="margin-bottom:1rem">
  {#if data?.host.nickname}<h1 style="margin:0">{data.host.nickname}</h1><span class="mono secondary">{ip}</span>{:else}<h1 class="mono" style="margin:0">{ip}</h1>{/if}
  <button class="small" onclick={startEdit} title="Set a nickname for this address">✎ {data?.host.nickname ? 'rename' : 'nickname'}</button>
  {#if data?.host.local}<span class="badge local">local</span>{/if}
  {#if data?.kind && data.kind !== 'other'}<span class="badge">{data.kind}</span>{/if}
  {#if data?.host.risk}<span class="badge {data.host.risk.critical ? 'critical' : data.host.risk.warning ? 'warning' : ''}" title="risk score {data.host.risk.score}"><a href={router.href('/alerts', { host: ip })} style="color:inherit">risk {data.host.risk.score}</a></span>{/if}
  {#if info?.country_code}<span class="flag" style="font-size:1.3rem" title={info.country ?? ''}>{flag(info.country_code)}</span>{/if}
  {#if trustedBy}<span class="badge good" title="excluded from alerts by pattern {trustedBy}">trusted · {trustedBy}</span>
    <button class="small" onclick={untrust} title="Remove from the trusted list so rules alert on this address again">Include in alerts</button>
  {:else}
    <button class="small" onclick={() => trust(ip)} title="Never raise alerts involving this address (all rules, incl. VirusTotal/AbuseIPDB flags)">Exclude from alerts</button>
  {/if}
  {#if exclMsg}<span class="small muted">{exclMsg}</span>{/if}
  <span class="spacer"></span>
  <a href={router.href('/flows', { ip })}>Raw flows →</a>
  {#if !data?.host.local}
    <button onclick={refresh} disabled={refreshing}>{refreshing ? 'Looking up…' : 'Refresh enrichment'}</button>
    {#if refreshMsg}<span class="small muted">{refreshMsg}</span>{/if}
  {/if}
</div>

{#if editing}
  <form class="card row" style="margin-bottom:1rem" onsubmit={saveNick}>
    <input placeholder="Nickname (empty = remove)" bind:value={nickInput} size="22" maxlength="100" />
    <select bind:value={kindInput}>{#each kinds as k}<option>{k}</option>{/each}</select>
    <input placeholder="Note (optional)" bind:value={noteInput} size="34" />
    <button type="submit" class="primary">Save</button>
    <button type="button" onclick={() => (editing = false)}>Cancel</button>
    {#if nickMsg}<span class="error small">{nickMsg}</span>{/if}
  </form>
{/if}

<Loading {error} loading={loading && !data} />
{#if data}
  {@const h = data.host}
  <div class="grid tiles">
    <StatTile label="Total" value={fmtBytes(h.bytes)} />
    <StatTile label="Received" value={fmtBytes(h.bytes_in)} sub="to this host" />
    <StatTile label="Sent" value={fmtBytes(h.bytes_out)} sub="from this host" />
    <StatTile label="Flows" value={fmtCompact(h.flows)} sub={fmtCompact(h.packets) + ' packets'} />
    <StatTile label="Peers" value={String(h.peers)} />
    <StatTile label="Last seen" value={h.last_seen ? fmtAgo(h.last_seen) : '–'} sub={h.first_seen ? 'first ' + fmtTime(h.first_seen) : ''} />
  </div>

  {#if data.alerts.length}
    <div class="card" style="margin-top:1rem; border-color: rgba(230,103,103,.4)">
      <h3>Active alerts ({data.alerts.length})</h3>
      <div class="overflow"><table>
        <thead><tr><th>Severity</th><th>Rule</th><th>What</th><th class="num">Seen</th><th class="num">Last</th></tr></thead>
        <tbody>
          {#each data.alerts as a (a.id)}
            <tr><td><span class="badge {a.severity === 'critical' ? 'critical' : a.severity === 'warning' ? 'warning' : ''}">{a.severity}</span></td>
              <td><a class="mono small" href={router.href('/rules', { open: a.rule })}>{a.rule}</a></td>
              <td class="wrap">{a.title}</td><td class="num">{a.count}</td><td class="num small">{fmtAgo(a.last_seen)}</td></tr>
          {/each}
        </tbody>
      </table></div>
      <a class="small" href={router.href('/alerts', { host: ip })}>All alerts for this host →</a>
    </div>
  {/if}

  <div class="grid cols-2" style="margin-top:1rem">
    <div class="card">
      <AreaChart points={data.timeseries} interval={data.window.interval_seconds} title="Throughput" />
    </div>
    <div class="card">
      <h3>Identity</h3>
      {#if !trustedBy && nameSuggestions.length}
        <div class="row small" style="margin-bottom:.5rem; gap:.3rem"><span class="muted">trust by name:</span>
          {#each nameSuggestions as p (p)}<button class="small" onclick={() => trust(p)} title="Exclude every address whose hostname matches {p}">{p}</button>{/each}
        </div>
      {/if}
      {#if info?.names?.length}
        <div class="small" style="margin-bottom:.5rem">Names: {#each info.names as n, i}{#if i}, {/if}<span class="mono" title="{n.source} · {n.hits}× · {fmtTime(n.last_seen)}">{n.name}</span>{/each}</div>
      {:else if h.names?.length}
        <div class="small" style="margin-bottom:.5rem">Names: {#each h.names as n, i}{#if i}, {/if}<span class="mono">{n}</span>{/each}</div>
      {/if}
      {#if info?.lists?.length}
        <div class="row small" style="margin-bottom:.5rem"><span class="badge critical">⛔ threat lists</span> {info.lists.join(', ')}</div>
      {/if}
      {#if h.local}
        <div class="muted">Local address — not enriched.</div>
      {:else if !info}
        <div class="muted">Not enriched yet. The worker will pick it up on the next pass, or click <em>Refresh enrichment</em>.</div>
      {:else}
        <dl>
          <dt>Hostname</dt><dd class="mono">{info.hostname ?? '–'}</dd>
          <dt>Location</dt><dd>{flag(info.country_code)} {[info.city, info.region, info.country].filter(Boolean).join(', ') || '–'}</dd>
          <dt>ASN</dt><dd>{#if info.asn}<a href={router.href('/hosts', { scope: 'external', asn: info.asn })}>{info.asn}</a> {info.as_org ?? ''}{:else}–{/if}</dd>
          <dt>Organisation</dt><dd>{info.org ?? '–'}</dd>
          <dt>ISP</dt><dd>{info.isp ?? '–'}</dd>
          <dt>Flags</dt><dd>
            {#if info.is_hosting}<span class="badge">hosting/DC</span>{/if}
            {#if info.is_proxy}<span class="badge warning">proxy/VPN</span>{/if}
            {#if info.is_mobile}<span class="badge">mobile</span>{/if}
            {#if !info.is_hosting && !info.is_proxy && !info.is_mobile}<span class="muted">none</span>{/if}
          </dd>
          <dt>Timezone</dt><dd>{info.timezone ?? '–'}</dd>
          <dt>Source</dt><dd class="small muted">{info.source ?? '–'} · {info.status} · looked up {fmtAgo(info.last_lookup)} ({info.attempts}×){#if info.error} · <span class="error">{info.error}</span>{/if}</dd>
        </dl>
        <h3 style="margin-top:1rem">VirusTotal</h3>
        {#if !vt}
          <div class="muted small">Not checked yet.</div>
        {:else if vt.status !== 'ok'}
          <div class="error small">Lookup failed: {vt.error}</div>
        {:else}
          {@const bad = (vt.malicious ?? 0) > 0 || (vt.suspicious ?? 0) > 0}
          <div class="row">
            <span class="badge {bad ? 'critical' : 'good'}">{bad ? '⚠ flagged' : '✓ clean'}</span>
            <span class="small">malicious <b>{vt.malicious}</b> · suspicious <b>{vt.suspicious}</b> · harmless {vt.harmless} · undetected {vt.undetected}</span>
          </div>
          <div class="small muted" style="margin-top:.35rem">
            reputation {vt.reputation ?? '–'}{#if vt.network} · network {vt.network}{/if}{#if vt.tags?.length} · tags: {vt.tags.join(', ')}{/if}
            · analysed {fmtTime(vt.last_analysis)} · checked {fmtAgo(vt.lookup_at)}
            · <a href="https://www.virustotal.com/gui/ip-address/{ip}" target="_blank" rel="noopener">open on VirusTotal ↗</a>
          </div>
        {/if}
        {#if info.reputation?.length}
          <h3 style="margin-top:1rem">Reputation</h3>
          {#each info.reputation as r}
            <div class="row small">
              <span class="badge {r.flagged ? 'critical' : 'good'}">{r.source}</span>
              {#if r.status !== 'ok'}<span class="error">{r.error}</span>
              {:else}<span>{r.flagged ? 'flagged' : 'clean'}{#if r.score != null} · score {r.score}{/if}</span>
                <span class="muted">checked {fmtAgo(r.lookup_at)}</span>{/if}
            </div>
          {/each}
        {/if}
      {/if}
    </div>
  </div>

  {#if data.ids_events?.length}
    <div class="card overflow" style="margin-top:1rem">
      <h3>IDS events ({data.ids_events.length})</h3>
      <table>
        <thead><tr><th>Time</th><th>Signature</th><th class="num">Sev</th><th>Category</th><th>Dir</th></tr></thead>
        <tbody>
          {#each data.ids_events as ev (ev.id)}
            <tr><td class="small">{fmtTime(ev.ts)}</td><td class="wrap">{ev.signature ?? '–'}</td>
              <td class="num"><span class="badge {ev.severity === 1 ? 'critical' : ev.severity === 2 ? 'warning' : ''}">{ev.severity ?? '–'}</span></td>
              <td class="small">{ev.category ?? '–'}</td>
              <td class="small mono">{ev.src_ip === ip ? '→ ' + (ev.dst_ip ?? '') : (ev.src_ip ?? '') + ' →'}</td></tr>
          {/each}
        </tbody>
      </table>
      <a class="small" href={router.href('/ids', { ip })}>All IDS events →</a>
    </div>
  {/if}

  <div class="grid wide-left" style="margin-top:1rem">
    <div class="card overflow">
      <h3>Peers ({data.peers.length})</h3>
      <table>
        <thead><tr>
          <Th sorter={peerSort} key="peer" label="Peer" />
          <Th sorter={peerSort} key="bytes" label="Total" num />
          <Th sorter={peerSort} key="bytes_in" label="Received" num />
          <Th sorter={peerSort} key="bytes_out" label="Sent" num />
          <Th sorter={peerSort} key="flows" label="Flows" num />
          <Th sorter={peerSort} key="last_seen" label="Last seen" num />
        </tr></thead>
        <tbody>
          {#each peers as p (p.ip)}
            <tr><td><IPLabel ip={p.ip} nickname={p.nickname} local={p.local} info={p.info} names={p.names} risk={p.risk} /></td>
              <td class="num">{fmtBytes(p.bytes)}</td><td class="num">{fmtBytes(p.bytes_in)}</td><td class="num">{fmtBytes(p.bytes_out)}</td>
              <td class="num">{fmtCompact(p.flows)}</td><td class="num">{fmtTime(p.last_seen)}</td></tr>
          {:else}<tr><td colspan="6" class="empty">No traffic in this window</td></tr>{/each}
        </tbody>
      </table>
    </div>
    <div class="card overflow">
      <h3>Ports / services</h3>
      <table>
        <thead><tr>
          <Th sorter={portSort} key="port" label="Port" />
          <Th sorter={portSort} key="service" label="Service" />
          <Th sorter={portSort} key="bytes" label="Bytes" num />
          <Th sorter={portSort} key="flows" label="Flows" num />
        </tr></thead>
        <tbody>
          {#each ports as p (p.port + '/' + p.proto)}
            <tr><td class="mono"><a href={router.href('/flows', { ip, port: String(p.port), proto: String(p.proto) })}>{p.port}/{p.name}</a></td>
              <td>{p.service || '–'}</td><td class="num">{fmtBytes(p.bytes)}</td><td class="num">{fmtCompact(p.flows)}</td></tr>
          {:else}<tr><td colspan="4" class="empty">No TCP/UDP traffic</td></tr>{/each}
        </tbody>
      </table>
    </div>
  </div>
{/if}

<style>
  dl { display: grid; grid-template-columns: max-content 1fr; gap: .3rem 1rem; margin: 0; font-size: .9rem; }
  dt { color: var(--text-muted); }
  dd { margin: 0; }
</style>
