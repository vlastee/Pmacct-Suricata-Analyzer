<script lang="ts">
  import { api, type EnrichmentStatus, type IPInfo } from '../lib/api'
  import { fmtAgo, fmtNum, flag, fmtTime } from '../lib/format'
  import { router } from '../lib/router.svelte'
  import StatTile from '../lib/components/StatTile.svelte'
  import IPLabel from '../lib/components/IPLabel.svelte'
  import Loading from '../lib/components/Loading.svelte'
  import Th from '../lib/components/Th.svelte'
  import { Sorter } from '../lib/sort.svelte'
  const sorter = new Sorter('updated_at')

  let { reloadKey }: { reloadKey: number } = $props()
  let status = $state<EnrichmentStatus | null>(null)
  let items = $state<IPInfo[]>([])
  let error = $state<string | null>(null)
  let search = $state('')
  let msg = $state('')

  let sorted = $derived(sorter.apply(items, (i, k) => k === 'country' ? (i.country ?? i.country_code) : k === 'org' ? (i.hostname ?? i.org ?? i.as_org ?? i.isp)
    : k === 'vt' ? (i.vt ? (i.vt.status !== 'ok' ? -1 : (i.vt.malicious ?? 0) * 1000 + (i.vt.suspicious ?? 0)) : null) : (i as any)[k]))
  let sys = $state<any>(null)
  let testMsg = $state('')
  async function load() {
    error = null
    try {
      const [s, l, sy] = await Promise.all([api.enrichmentStatus(), api.ipList(search, 100), api.systemStatus().catch(() => null)])
      status = s; items = l.items; sys = sy
    } catch (e: any) { error = e.message }
  }
  $effect(() => { void reloadKey; load() })
  async function run() {
    msg = ''
    try { await api.enrichmentRun(); msg = 'Pass queued'; setTimeout(load, 1500) } catch (e: any) { msg = e.message }
  }
  let sevMsg = $state<string | null>(null)
  async function setMinSeverity(sev: string) {
    sevMsg = 'saving…'
    try { const st = await api.notifySettings(sev); sys.notifications = st; sevMsg = `alerts at ${st.min_severity} and above are sent` } catch (e: any) { sevMsg = e.message }
  }
  async function testNotify() {
    testMsg = 'sending…'
    try { const r = await api.notifyTest(); testMsg = Object.entries(r.results).map(([k, v]) => `${k}: ${v}`).join(' · ') } catch (e: any) { testMsg = e.message }
  }
</script>

<Loading {error} />
{#if status}
  {@const t = status.table}
  {@const geo = status.lanes?.geo}
  {@const vt = status.lanes?.vt}
  <div class="row" style="margin-bottom:1rem">
    <span class="badge {status.enabled ? 'good' : 'warning'}">{status.enabled ? 'enrichment enabled' : 'enrichment disabled'}</span>
    <span class="spacer"></span>
    <button onclick={run} disabled={!status.enabled}>Run a pass now</button>
    {#if msg}<span class="small muted">{msg}</span>{/if}
  </div>

  {#if sys}
    <div class="grid cols-3" style="margin-bottom:1rem">
      <div class="card">
        <h3>Threat feeds</h3>
        {#if sys.threat_lists?.length}
          <table><tbody>
            {#each sys.threat_lists as l}<tr><td class="mono small">{l.list}</td><td class="num">{fmtNum(l.entries)}</td><td class="num small muted">{fmtAgo(l.updated)}</td></tr>{/each}
          </tbody></table>
          <div class="small muted" style="margin-top:.4rem">{fmtNum(sys.threat_lists.reduce((a: number, b: any) => a + b.entries, 0))} total IPs/CIDRs matched locally · refresh {sys.feeds?.interval ?? ''}</div>
        {:else}<div class="muted small">No feeds loaded (set THREAT_FEEDS).</div>{/if}
        {#if sys.feeds?.results}{@const errs = Object.entries(sys.feeds.results).filter(([, v]: [string, any]) => v.error)}
          {#if errs.length}<div class="small error" style="margin-top:.4rem">errors: {errs.map(([k, v]: [string, any]) => `${k} (${v.error})`).join(', ')}</div>{/if}
        {/if}
      </div>
      <div class="card">
        <h3>Reputation & IDS</h3>
        {#if sys.reputation?.length}
          <table><tbody>
            {#each sys.reputation as r}<tr><td class="mono small">{r.source}</td><td class="num small">{fmtNum(r.total)} checked</td><td class="num"><span class="badge {r.flagged ? 'critical' : ''}">{r.flagged} flagged</span></td></tr>{/each}
          </tbody></table>
        {:else}<div class="muted small">No reputation sources (set ABUSEIPDB_KEY / GREYNOISE_KEY).</div>{/if}
        <div class="small muted" style="margin-top:.5rem">
          Suricata IDS: {#if sys.suricata_enabled}<span class="badge good">listening {sys.suricata?.listen}</span> {fmtNum(sys.suricata?.received ?? 0)} events{:else}<span class="badge">off</span>{/if}
        </div>
      </div>
      <div class="card">
        <h3>Notifications</h3>
        {#if sys.notifications?.channels?.length}
          <div class="row" style="gap:.3rem">{#each sys.notifications.channels as c}<span class="badge good">{c}</span>{/each}</div>
          <div class="row small muted" style="margin-top:.4rem">
            <label class="row" style="gap:.3rem" title="Alerts at this severity and above are delivered; lower ones are only shown in the UI">send
              <select value={sys.notifications.min_severity} onchange={(e) => setMinSeverity(e.currentTarget.value)}>
                <option value="critical">critical only</option><option value="warning">warning and above</option><option value="info">everything (info+)</option>
              </select>
            </label>
            · {sys.notifications.digest === '0s' ? 'immediate' : 'digest ' + sys.notifications.digest}{#if sys.notifications.quiet_hours} · quiet {sys.notifications.quiet_hours}{/if} · {fmtNum(sys.notifications.sent)} sent
          </div>
          {#if sevMsg}<div class="small muted" style="margin-top:.3rem">{sevMsg}</div>{/if}
          <button class="small" style="margin-top:.5rem" onclick={testNotify}>Send test</button>
          {#if testMsg}<div class="small muted" style="margin-top:.3rem">{testMsg}</div>{/if}
        {:else}<div class="muted small">No channels configured (set NOTIFY_* variables).</div>{/if}
      </div>
    </div>
  {/if}
  <div class="grid cols-2">
    <div class="card">
      <h3>Geo / ASN lane {#if geo}<span class="muted">· {geo.provider}</span>{/if}</h3>
      <div class="grid tiles">
        <StatTile label="Known IPs" value={fmtNum(t.total)} />
        <StatTile label="Resolved" value={fmtNum(t.ok)} sub={`${t.stale} stale`} />
        <StatTile label="Pending" value={fmtNum(t.pending)} />
        <StatTile label="Failed" value={fmtNum(t.failed)} />
      </div>
      {#if geo}
        <div class="small muted" style="margin-top:.75rem">
          every {geo.interval} · refresh after {geo.refresh_after} · rate limit {geo.rate_limit} ·
          last run {fmtAgo(geo.last_run)} ({geo.last_batch_size} candidates) · {fmtNum(geo.lookups)} lookups / {fmtNum(geo.failures)} failures since start
          {#if geo.running}· <span class="badge">running</span>{/if}
        </div>
      {/if}
    </div>
    <div class="card">
      <h3>VirusTotal lane {#if vt && !vt.enabled}<span class="badge warning">disabled — set VT_API_KEY</span>{/if}</h3>
      <div class="grid tiles">
        <StatTile label="Checked" value={fmtNum(t.vt_done)} sub={`${t.vt_stale} stale`} />
        <StatTile label="Flagged" value={fmtNum(t.vt_flagged)} />
        <StatTile label="Never checked" value={fmtNum(t.vt_never)} />
        <StatTile label="Quota today" value={vt?.daily_quota ? `${vt.quota_used ?? t.vt_used_today} / ${vt.daily_quota}` : fmtNum(t.vt_used_today)} sub={vt?.quota_hit ? 'quota exhausted' : ''} />
        <StatTile label="Quota this month" value={vt?.monthly_quota ? `${vt.quota_used_month ?? t.vt_used_month} / ${fmtNum(vt.monthly_quota)}` : fmtNum(t.vt_used_month)} />
      </div>
      {#if vt}
        <div class="small muted" style="margin-top:.75rem">
          Strategy: never-checked IPs first (largest traffic first), then records older than {vt.refresh_after} that still appear in the last 24h of traffic; {vt.rate_limit} between requests, hard daily and monthly caps.
          {#if vt.enabled}· last run {fmtAgo(vt.last_run)} · {fmtNum(vt.failures)} failures since start{/if}
        </div>
      {/if}
    </div>
  </div>

  <div class="card overflow" style="margin-top:1rem">
    <form class="row" style="margin-bottom:.75rem" onsubmit={(e) => { e.preventDefault(); load() }}>
      <h3 style="margin:0">Enriched addresses</h3>
      <span class="spacer"></span>
      <input placeholder="Search IP, host, org, country" bind:value={search} size="28" />
      <button type="submit">Search</button>
    </form>
    <table>
      <thead><tr>
        <Th sorter={sorter} key="ip" label="IP" />
        <Th sorter={sorter} key="country" label="Country" />
        <Th sorter={sorter} key="asn" label="ASN" />
        <Th sorter={sorter} key="org" label="Organisation" />
        <Th sorter={sorter} key="status" label="Geo" />
        <Th sorter={sorter} key="vt" label="VT" num />
        <Th sorter={sorter} key="updated_at" label="Updated" num />
      </tr></thead>
      <tbody>
        {#each sorted as i (i.ip)}
          <tr>
            <td><IPLabel ip={i.ip} /></td>
            <td><span class="flag">{flag(i.country_code)}</span> {i.country ?? i.country_code ?? '–'}</td>
            <td class="small">{#if i.asn}<a href={router.href('/hosts', { scope: 'external', asn: i.asn })}>{i.asn}</a>{:else}–{/if}</td>
            <td class="small">{i.hostname ?? i.org ?? i.as_org ?? i.isp ?? '–'}</td>
            <td><span class="badge {i.status === 'ok' ? 'good' : i.status === 'failed' ? 'critical' : ''}" title={i.error ?? ''}>{i.status}</span></td>
            <td>
              {#if i.vt}
                {#if i.vt.status !== 'ok'}<span class="badge critical" title={i.vt.error ?? ''}>error</span>
                {:else if (i.vt.malicious ?? 0) > 0 || (i.vt.suspicious ?? 0) > 0}<span class="badge critical">{i.vt.malicious}/{i.vt.suspicious}</span>
                {:else}<span class="badge good">clean</span>{/if}
              {:else}<span class="muted small">–</span>{/if}
            </td>
            <td class="num small">{fmtTime(i.updated_at)}</td>
          </tr>
        {:else}<tr><td colspan="7" class="empty">Nothing enriched yet</td></tr>{/each}
      </tbody>
    </table>
  </div>
{/if}
