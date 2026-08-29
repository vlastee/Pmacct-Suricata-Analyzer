<script lang="ts">
  import { untrack } from 'svelte'
  import { api, type CustomRuleSpec, type Finding, type RuleInfo } from '../api'

  let { initial, builtins, isNew, onsaved, oncancel, ondeleted }: {
    initial: CustomRuleSpec; builtins: RuleInfo[]; isNew: boolean
    onsaved: (r: RuleInfo) => void; oncancel: () => void; ondeleted?: () => void
  } = $props()

  const toStr = (v: any) => (Array.isArray(v) ? v.join(', ') : v == null ? '' : String(v))
  function paramStrings(base: string, values?: Record<string, any>): Record<string, string> {
    const b = builtins.find(x => x.name === base)
    const out: Record<string, string> = {}
    for (const p of b?.params ?? []) out[p.name] = toStr(values?.[p.name] ?? p.default)
    return out
  }
  // The editor snapshots `initial` once; the parent re-keys the component to start over.
  let d = $state(untrack(() => {
    const base = initial.base ?? builtins[0]?.name ?? ''
    return {
      name: initial.name, title: initial.title, description: initial.description, kind: initial.kind,
      base, sql: initial.sql ?? '', severity: initial.severity || 'warning',
      interval: initial.interval, window: initial.window, enabled: initial.enabled ?? true,
      exempt: (initial.exempt_hosts ?? []).join(', '), params: paramStrings(base, initial.params),
    }
  }))
  let baseInfo = $derived(builtins.find(x => x.name === d.base))
  let msg = $state<string | null>(null)
  let busy = $state(false)
  let preview = $state<Finding[] | null>(null)
  let showHelp = $state(false)

  function onBaseChange() {
    d.params = paramStrings(d.base)
    if (baseInfo) { d.interval = baseInfo.default_interval; d.window = baseInfo.default_window }
  }
  function spec(): CustomRuleSpec {
    const s: CustomRuleSpec = {
      name: d.name.trim(), title: d.title.trim(), description: d.description.trim(), kind: d.kind, severity: d.severity,
      interval: d.interval.trim(), window: d.window.trim(), enabled: d.enabled,
      exempt_hosts: d.exempt.split(',').map(x => x.trim()).filter(Boolean),
    }
    if (d.kind === 'sql') s.sql = d.sql
    else {
      s.base = d.base
      const params: Record<string, any> = {}
      for (const p of baseInfo?.params ?? []) {
        const raw = d.params[p.name] ?? ''
        params[p.name] = Array.isArray(p.default)
          ? raw.split(',').map(x => x.trim()).filter(Boolean).map(x => (isNaN(+x) ? x : +x))
          : (isNaN(+raw) || raw === '' ? raw : +raw)
      }
      s.params = params
    }
    return s
  }
  async function doPreview() {
    busy = true; msg = null; preview = null
    try { preview = (await api.previewCustomRule(spec())).findings } catch (e: any) { msg = e.message } finally { busy = false }
  }
  async function save() {
    busy = true; msg = null
    try {
      const s = spec()
      const r = isNew ? await api.createCustomRule(s) : await api.updateCustomRule(s.name, s)
      msg = 'saved'; onsaved(r)
    } catch (e: any) { msg = e.message } finally { busy = false }
  }
  async function del() {
    if (!confirm(`Delete rule "${d.name}"? Alerts it raised are kept.`)) return
    busy = true; msg = null
    try { await api.deleteCustomRule(d.name); ondeleted?.() } catch (e: any) { msg = e.message } finally { busy = false }
  }

  const contract = [
    'Runs read-only with a 30 s timeout, once per interval. Parameters: $1 = window start, $2 = window end (timestamptz), $3 = local networks (cidr[]).',
    'Return a "host" column (the local device; inet or text). Optional: peer, port, title, severity (info|warning|critical), details (jsonb), key (extra dedupe discriminator).',
    'One alert per rule + host + peer + port + key — aggregate with GROUP BY; at most 500 rows per run.',
    'Tables: acct(ip_src, ip_dst, port_src, port_dst, ip_proto, packets, bytes, stamp_inserted) · ip_info(ip, hostname, country_code, asn, as_org, is_hosting, is_proxy, vt_malicious, …) · ip_names(ip, name, source) · ip_nicknames(ip, nickname, kind) · ids_events(ts, src_ip, dst_ip, dst_port, sid, signature, severity) · threat_lists(net, list) · host_hourly(host, hour, bytes_in, bytes_out, flows, peers, ports) · host_peer_daily(host, peer, day, bytes, flows) · alerts.',
  ]
  const examples = [
    { title: 'Upload over 1 GB to one external peer', sql: `SELECT ip_src AS host, ip_dst AS peer, SUM(bytes) AS bytes,
       format('%s sent %s MB to %s', ip_src, (SUM(bytes)/1048576)::int, ip_dst) AS title,
       jsonb_build_object('bytes', SUM(bytes)) AS details
FROM acct
WHERE stamp_inserted >= $1 AND stamp_inserted < $2
  AND ip_src <<= ANY($3::cidr[]) AND NOT (ip_dst <<= ANY($3::cidr[]))
GROUP BY ip_src, ip_dst
HAVING SUM(bytes) > 1073741824` },
    { title: 'Any contact with a watch-listed network', sql: `SELECT ip_src AS host, ip_dst AS peer, port_dst AS port, 'critical' AS severity,
       format('%s contacted watched %s:%s', ip_src, ip_dst, port_dst) AS title
FROM acct
WHERE stamp_inserted >= $1 AND stamp_inserted < $2
  AND ip_dst <<= ANY(ARRAY['203.0.113.0/24', '198.51.100.7/32']::cidr[])
GROUP BY ip_src, ip_dst, port_dst` },
    { title: 'A Suricata signature fired N times from one host', sql: `SELECT src_ip AS host, sid::text AS key,
       format('%s triggered "%s" %s times', src_ip, signature, COUNT(*)) AS title,
       jsonb_build_object('sid', sid, 'count', COUNT(*)) AS details
FROM ids_events
WHERE ts >= $1 AND ts < $2 AND sid = 2210050
GROUP BY src_ip, sid, signature
HAVING COUNT(*) >= 10` },
  ]
</script>

<div class="editor">
  <div class="fields">
    <label>name<input bind:value={d.name} disabled={!isNew} placeholder="my_rule" /><span class="hint">a-z, 0-9 and _ · cannot change later</span></label>
    <label>title<input bind:value={d.title} placeholder="Shown on alerts" /></label>
    <label class="span2">description<input bind:value={d.description} /></label>
    <label>logic
      <select bind:value={d.kind}><option value="sql">SQL query</option><option value="builtin">built-in detector</option></select>
      <span class="hint">{d.kind === 'sql' ? 'your own SELECT — see the reference below' : 'reuse a built-in rule with your own settings'}</span>
    </label>
    {#if d.kind === 'builtin'}
      <label>base rule
        <select bind:value={d.base} onchange={onBaseChange}>{#each builtins as b (b.name)}<option value={b.name}>{b.title} ({b.name})</option>{/each}</select>
        <span class="hint">{baseInfo?.description ?? ''}</span>
      </label>
      {#each baseInfo?.params ?? [] as p (p.name)}
        <label title={p.description}>{p.name}<input bind:value={d.params[p.name]} /><span class="hint">{p.description}</span></label>
      {/each}
    {/if}
    <label>severity<select bind:value={d.severity}><option>info</option><option>warning</option><option>critical</option></select></label>
    <label>interval<input bind:value={d.interval} placeholder="1m" /><span class="hint">how often it runs (30s – 168h)</span></label>
    <label>window<input bind:value={d.window} placeholder="10m" /><span class="hint">how far back it looks (1m – 720h)</span></label>
    <label>exempt hosts<input bind:value={d.exempt} placeholder="10.0.0.5, Office-PC" /><span class="hint">comma-separated IPs or nicknames</span></label>
    <label class="check"><span><input type="checkbox" bind:checked={d.enabled} /> enabled</span></label>
  </div>
  {#if d.kind === 'sql'}
    <div class="sqlhead row small">
      <span>SQL</span>
      <button class="x" onclick={() => (showHelp = !showHelp)}>{showHelp ? 'hide reference' : 'reference & examples'}</button>
    </div>
    <textarea bind:value={d.sql} rows="10" spellcheck="false" placeholder="SELECT ip_src AS host, … FROM acct WHERE stamp_inserted >= $1 AND stamp_inserted < $2 …"></textarea>
    {#if showHelp}
      <div class="help small">
        <ul>{#each contract as c}<li>{c}</li>{/each}</ul>
        {#each examples as ex}
          <div class="row"><strong>{ex.title}</strong><button class="x" onclick={() => (d.sql = ex.sql)}>use</button></div>
          <pre>{ex.sql}</pre>
        {/each}
      </div>
    {/if}
  {/if}
  <div class="row" style="margin-top:.6rem">
    <button onclick={doPreview} disabled={busy}>Preview</button>
    <button class="primary" onclick={save} disabled={busy}>{isNew ? 'Create' : 'Save'}</button>
    <button onclick={oncancel} disabled={busy}>Cancel</button>
    {#if !isNew && ondeleted}<button class="danger" onclick={del} disabled={busy}>Delete</button>{/if}
    {#if msg}<span class="small" class:muted={msg === 'saved'} class:err={msg !== 'saved'}>{msg}</span>{/if}
  </div>
  {#if preview}
    <div class="card overflow" style="margin-top:.6rem">
      <h3>Preview — {preview.length} finding{preview.length === 1 ? '' : 's'} right now <span class="small muted">(nothing was raised)</span></h3>
      {#if preview.length}
        <table>
          <thead><tr><th>Host</th><th>Peer</th><th class="num">Port</th><th>Severity</th><th>Title</th></tr></thead>
          <tbody>
            {#each preview as f, i (i)}
              <tr><td class="mono">{f.host ?? '–'}</td><td class="mono">{f.peer ?? '–'}</td><td class="num">{f.port || '–'}</td>
                <td><span class="badge {f.severity}">{f.severity}</span></td><td class="wrap">{f.title}</td></tr>
            {/each}
          </tbody>
        </table>
      {:else}<div class="empty">No findings in the current window — the rule is valid, nothing matches right now.</div>{/if}
    </div>
  {/if}
</div>

<style>
  .editor { margin-top: .5rem; }
  .fields { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: .6rem; margin: .5rem 0; }
  label { display: flex; flex-direction: column; gap: .2rem; font-size: .82rem; color: var(--text-secondary); }
  label.span2 { grid-column: span 2; }
  label.check { justify-content: end; }
  .hint { color: var(--text-muted); font-size: .72rem; }
  .sqlhead { justify-content: space-between; color: var(--text-secondary); margin-top: .4rem; }
  textarea { width: 100%; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .8rem; background: var(--surface-2); color: inherit; border: 1px solid var(--border); border-radius: var(--radius); padding: .5rem; box-sizing: border-box; }
  .help { margin-top: .5rem; color: var(--text-secondary); }
  .help ul { margin: 0 0 .5rem 1rem; padding: 0; }
  .help pre { margin: .2rem 0 .6rem; font-size: .75rem; white-space: pre-wrap; background: var(--surface-2); padding: .4rem; border-radius: var(--radius); }
  .x { border: 0; background: transparent; color: var(--accent, #8dbcf5); cursor: pointer; padding: 0 .2rem; }
  .danger { color: #f2a2a2; }
  .err { color: #f2a2a2; }
  .wrap { white-space: normal; }
</style>
