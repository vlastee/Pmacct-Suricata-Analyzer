<script lang="ts">
  import { api, type CustomRuleSpec, type Finding, type RuleInfo } from '../lib/api'
  import { router } from '../lib/router.svelte'
  import { fmtAgo } from '../lib/format'
  import Severity from '../lib/components/Severity.svelte'
  import Loading from '../lib/components/Loading.svelte'
  import RuleEditor from '../lib/components/RuleEditor.svelte'
  import { exclusions } from '../lib/exclusions.svelte'
  import { fmtTime } from '../lib/format'

  let { reloadKey }: { reloadKey: number } = $props()
  let items = $state<RuleInfo[]>([])
  let enabled = $state(true)
  let error = $state<string | null>(null)
  let open = $state<string | null>(null)
  let msg = $state<Record<string, string>>({})
  let previews = $state<Record<string, Finding[]>>({})
  type Draft = { values: Record<string, string>; severity: string; exempt: string; interval: string; window: string }
  let drafts = $state<Record<string, Draft>>({})
  // Editor for a new rule (blank, or pre-filled by "Duplicate" on a built-in).
  let creating = $state<CustomRuleSpec | null>(null)
  let editorKey = $state(0)
  let builtins = $derived(items.filter(r => !r.custom && r.name !== 'ids'))

  $effect(() => { open = router.route.query.get('open') })

  async function load() {
    error = null
    try { const r = await api.rules(); items = r.items; enabled = r.enabled } catch (e: any) { error = e.message }
  }
  $effect(() => { void reloadKey; load() })

  // Go prints durations as "1h0m0s"; show the short form and accept either.
  function tidy(s: string): string {
    const m = s.match(/^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?$/)
    if (!m) return s
    const parts: string[] = []
    if (+m[1]) parts.push(m[1] + 'h')
    if (+m[2]) parts.push(m[2] + 'm')
    if (+m[3]) parts.push(m[3] + 's')
    return parts.join('') || s
  }
  function draft(r: RuleInfo): Draft {
    if (!drafts[r.name]) {
      const values: Record<string, string> = {}
      for (const [k, v] of Object.entries(r.values)) values[k] = Array.isArray(v) ? v.join(', ') : String(v)
      drafts[r.name] = { values, severity: r.severity, exempt: r.exempt_hosts.join(', '), interval: tidy(r.interval), window: tidy(r.window) }
    }
    return drafts[r.name]
  }
  function specOf(r: RuleInfo): CustomRuleSpec {
    return { name: r.name, title: r.title, description: r.description, kind: r.kind ?? 'sql', base: r.base, sql: r.sql, params: r.values,
      severity: r.severity, interval: tidy(r.interval), window: tidy(r.window), enabled: r.enabled, exempt_hosts: r.exempt_hosts }
  }
  async function toggle(r: RuleInfo) {
    try { await api.updateRule(r.name, { enabled: !r.enabled }); await load() } catch (e: any) { msg[r.name] = e.message }
  }
  async function save(r: RuleInfo) {
    const d = drafts[r.name]
    const params: Record<string, any> = {}
    for (const p of r.params) {
      const raw = d.values[p.name] ?? ''
      params[p.name] = Array.isArray(p.default)
        ? raw.split(',').map(s => s.trim()).filter(Boolean).map(x => (isNaN(+x) ? x : +x))
        : (isNaN(+raw) || raw === '' ? raw : +raw)
    }
    try {
      await api.updateRule(r.name, { severity: d.severity, params, exempt_hosts: d.exempt.split(',').map(s => s.trim()).filter(Boolean), interval: d.interval.trim(), window: d.window.trim() })
      msg[r.name] = 'saved'; delete drafts[r.name]; await load()
    } catch (e: any) { msg[r.name] = e.message }
  }
  async function run(r: RuleInfo) {
    msg[r.name] = 'running…'
    try { const res = await api.runRule(r.name); msg[r.name] = `raised ${res.raised.length}`; await load() } catch (e: any) { msg[r.name] = e.message }
  }
  async function preview(r: RuleInfo) {
    msg[r.name] = 'previewing…'
    try { previews[r.name] = (await api.previewRule(r.name)).findings; msg[r.name] = `${previews[r.name].length} finding(s) right now — nothing raised` } catch (e: any) { msg[r.name] = e.message }
  }
  // trusted list
  let exclPattern = $state('')
  let exclNote = $state('')
  let exclMsg = $state('')
  async function addExclusion(e: Event) {
    e.preventDefault(); exclMsg = ''
    try {
      const r = await exclusions.add(exclPattern, exclNote)
      exclMsg = `added ${r.item.pattern} (${r.item.kind})` + (r.resolved ? ` · ${r.resolved} open alert${r.resolved === 1 ? '' : 's'} resolved` : '')
      exclPattern = ''; exclNote = ''
    } catch (err: any) { exclMsg = err.message }
  }
  async function removeExclusion(id: number) {
    try { await exclusions.remove(id); exclMsg = 'removed' } catch (err: any) { exclMsg = err.message }
  }
  function newRule() {
    creating = { name: '', title: '', description: '', kind: 'sql', sql: '', severity: 'warning', interval: '5m', window: '1h', enabled: true, exempt_hosts: [] }
    editorKey++; window.scrollTo({ top: 0, behavior: 'smooth' })
  }
  function duplicate(r: RuleInfo) {
    creating = { name: r.name + '_copy', title: r.title + ' (copy)', description: r.description, kind: 'builtin', base: r.name, params: r.values,
      severity: r.severity, interval: tidy(r.interval), window: tidy(r.window), enabled: true, exempt_hosts: r.exempt_hosts }
    editorKey++; window.scrollTo({ top: 0, behavior: 'smooth' })
  }
</script>

{#if !enabled}<div class="card">The rules engine is disabled (RULES_ENABLED=false).</div>{/if}
<Loading {error} />
<div class="row" style="margin-bottom:.6rem">
  <p class="muted small" style="margin:0">Detection rules run on a schedule ({items.length} rules). Adjust thresholds, severity, how often a rule runs and how far back it looks, or exempt trusted hosts. “Preview” shows what a rule would raise right now; “Run now” raises it (ignoring the enabled flag). Built-ins can be duplicated with different settings; custom rules can also be your own SQL.</p>
  <span class="spacer"></span>
  <button class="primary" onclick={newRule}>New rule</button>
</div>

{#if creating}
  {#key editorKey}
    <div class="card" style="margin-bottom:.8rem">
      <h3>New custom rule</h3>
      <RuleEditor initial={creating} {builtins} isNew={true}
        onsaved={(r) => { creating = null; open = r.name; load() }} oncancel={() => (creating = null)} />
    </div>
  {/key}
{/if}

<div class="grid" style="gap:.6rem">
  {#each items as r (r.name)}
    <div class="card rule" class:off={!r.enabled}>
      <div class="row" style="cursor:pointer" role="button" tabindex="0"
        onclick={() => (open = open === r.name ? null : r.name)}
        onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open = open === r.name ? null : r.name } }}>
        <Severity sev={r.severity} />
        <strong>{r.title}</strong>
        <span class="mono small muted">{r.name}</span>
        {#if r.custom}<span class="badge local" title={r.kind === 'sql' ? 'your own SQL' : `built on ${r.base}`}>custom · {r.kind}</span>{/if}
        {#if !r.enabled}<span class="badge">disabled</span>{/if}
        <span class="spacer"></span>
        {#if r.last_error}<span class="badge critical" title={r.last_error}>error</span>{/if}
        <span class="small muted">every {tidy(r.interval)} · {r.last_run ? `ran ${fmtAgo(r.last_run)} · ${r.last_findings} found · ${r.last_ms}ms` : 'not run yet'}</span>
        <button class="small" onclick={(e) => { e.stopPropagation(); toggle(r) }}>{r.enabled ? 'Disable' : 'Enable'}</button>
        <button class="small" onclick={(e) => { e.stopPropagation(); preview(r) }}>Preview</button>
        <button class="small" onclick={(e) => { e.stopPropagation(); run(r) }}>Run now</button>
        {#if !r.custom && r.name !== 'ids'}<button class="small" onclick={(e) => { e.stopPropagation(); duplicate(r) }} title="Create a custom rule with this detector and your own settings">Duplicate</button>{/if}
      </div>
      {#if open === r.name}
        <div class="body">
          <p class="secondary small">{r.description}</p>
          {#if r.custom}
            <RuleEditor initial={specOf(r)} {builtins} isNew={false}
              onsaved={() => { msg[r.name] = 'saved'; load() }} oncancel={() => (open = null)} ondeleted={() => { open = null; load() }} />
          {:else}
            {@const d = draft(r)}
            <div class="fields">
              <label>Severity
                <select bind:value={d.severity}><option>info</option><option>warning</option><option>critical</option></select>
                <span class="hint">default {r.default_severity}</span>
              </label>
              <label title="How often the rule is evaluated">interval
                <input bind:value={d.interval} size="10" placeholder={tidy(r.default_interval)} />
                <span class="hint">default {tidy(r.default_interval)} · 30s – 168h</span>
              </label>
              <label title="How far back each evaluation looks">window
                <input bind:value={d.window} size="10" placeholder={tidy(r.default_window)} />
                <span class="hint">default {tidy(r.default_window)} · 1m – 720h</span>
              </label>
              {#each r.params as p (p.name)}
                <label title={p.description}>{p.name}
                  <input bind:value={d.values[p.name]} size="20" />
                  <span class="hint">{p.description}</span>
                </label>
              {/each}
              <label title="IPs or nicknames never alerted by this rule">exempt hosts
                <input bind:value={d.exempt} size="30" placeholder="10.0.0.5, Office-PC" />
                <span class="hint">comma-separated IPs or nicknames</span>
              </label>
            </div>
            <div class="row">
              <button class="primary" onclick={() => save(r)}>Save</button>
              <a class="small" href={router.href('/alerts', { rule: r.name })}>View alerts →</a>
              {#if msg[r.name]}<span class="small muted">{msg[r.name]}</span>{/if}
            </div>
          {/if}
        </div>
      {:else if msg[r.name]}
        <div class="small muted" style="margin-top:.4rem">{msg[r.name]}</div>
      {/if}
      {#if previews[r.name]}
        <div class="overflow" style="margin-top:.6rem">
          {#if previews[r.name].length}
            <table>
              <thead><tr><th>Host</th><th>Peer</th><th class="num">Port</th><th>Severity</th><th>Title</th><th></th></tr></thead>
              <tbody>
                {#each previews[r.name] as f, i (i)}
                  <tr><td class="mono">{f.host ?? '–'}</td><td class="mono">{f.peer ?? '–'}</td><td class="num">{f.port || '–'}</td>
                    <td><span class="badge {f.severity}">{f.severity}</span></td><td class="wrap">{f.title}</td>
                    <td class="num"><button class="x" onclick={() => delete previews[r.name]} title="Close preview">×</button></td></tr>
                {/each}
              </tbody>
            </table>
          {:else}<div class="small muted">Preview: no findings in the current window. <button class="x" onclick={() => delete previews[r.name]}>×</button></div>{/if}
        </div>
      {/if}
    </div>
  {/each}
</div>

<div class="card" style="margin-top:1rem">
  <h3>Trusted list — excluded from alerts</h3>
  <p class="muted small">Addresses here never raise alerts from any rule, even when VirusTotal, AbuseIPDB or a threat feed flags them. Use an IP (<span class="mono">10.0.0.5</span>), a network (<span class="mono">203.0.113.0/24</span>) or a hostname pattern matched against reverse-DNS and DNS/TLS-learned names (<span class="mono">*.anthropic.com</span>, <span class="mono">discord.com</span>). Adding one resolves the open alerts it covers. Per-rule exemptions above still work for narrower cases.</p>
  <form class="row" onsubmit={addExclusion} style="margin-bottom:.6rem">
    <input placeholder="IP, CIDR or *.hostname" bind:value={exclPattern} size="28" required />
    <input placeholder="note (optional)" bind:value={exclNote} size="30" />
    <button type="submit" class="primary">Add</button>
    {#if exclMsg}<span class="small muted">{exclMsg}</span>{/if}
  </form>
  {#if exclusions.items.length}
    <div class="overflow"><table>
      <thead><tr><th>Pattern</th><th>Kind</th><th>Note</th><th class="num">Added</th><th></th></tr></thead>
      <tbody>
        {#each exclusions.items as e (e.id)}
          <tr><td class="mono">{e.pattern}</td><td class="small">{e.kind}</td><td class="small">{e.note || '–'}</td>
            <td class="num small muted">{fmtTime(e.created_at)}</td>
            <td class="num"><button class="small" onclick={() => removeExclusion(e.id)} title="Alerts on matching addresses again">Include in alerts</button></td></tr>
        {/each}
      </tbody>
    </table></div>
  {:else}<div class="small muted">Nothing excluded. Use “Exclude from alerts” on a host page or in an alert’s details, or add a pattern above.</div>{/if}
</div>

<style>
  .rule.off { opacity: .7; }
  .body { margin-top: .75rem; border-top: 1px solid var(--border); padding-top: .75rem; }
  .fields { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: .6rem; margin: .5rem 0; }
  label { display: flex; flex-direction: column; gap: .2rem; font-size: .82rem; color: var(--text-secondary); }
  .hint { color: var(--text-muted); font-size: .72rem; }
  .wrap { white-space: normal; }
  .x { border: 0; background: transparent; color: inherit; cursor: pointer; padding: 0 .2rem; }
</style>
