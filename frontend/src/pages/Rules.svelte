<script lang="ts">
  import { api, type RuleInfo } from '../lib/api'
  import { router } from '../lib/router.svelte'
  import { fmtAgo } from '../lib/format'
  import Severity from '../lib/components/Severity.svelte'
  import Loading from '../lib/components/Loading.svelte'

  let { reloadKey }: { reloadKey: number } = $props()
  let items = $state<RuleInfo[]>([])
  let enabled = $state(true)
  let error = $state<string | null>(null)
  let open = $state<string | null>(null)
  let msg = $state<Record<string, string>>({})
  let drafts = $state<Record<string, { values: Record<string, string>; severity: string; exempt: string }>>({})

  $effect(() => { open = router.route.query.get('open') })

  async function load() {
    error = null
    try { const r = await api.rules(); items = r.items; enabled = r.enabled } catch (e: any) { error = e.message }
  }
  $effect(() => { void reloadKey; load() })

  function draft(r: RuleInfo) {
    if (!drafts[r.name]) {
      const values: Record<string, string> = {}
      for (const [k, v] of Object.entries(r.values)) values[k] = Array.isArray(v) ? v.join(', ') : String(v)
      drafts[r.name] = { values, severity: r.severity, exempt: r.exempt_hosts.join(', ') }
    }
    return drafts[r.name]
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
      await api.updateRule(r.name, { severity: d.severity, params, exempt_hosts: d.exempt.split(',').map(s => s.trim()).filter(Boolean) })
      msg[r.name] = 'saved'; await load()
    } catch (e: any) { msg[r.name] = e.message }
  }
  async function run(r: RuleInfo) {
    msg[r.name] = 'running…'
    try { const res = await api.runRule(r.name); msg[r.name] = `raised ${res.raised.length}`; await load() } catch (e: any) { msg[r.name] = e.message }
  }
</script>

{#if !enabled}<div class="card">The rules engine is disabled (RULES_ENABLED=false).</div>{/if}
<Loading {error} />
<p class="muted small">Detection rules run on a schedule ({items.length} rules). Adjust thresholds, change severity, disable a rule, or exempt trusted hosts (by IP or nickname). “Run now” evaluates immediately, ignoring the enabled flag.</p>

<div class="grid" style="gap:.6rem">
  {#each items as r (r.name)}
    <div class="card rule" class:off={!r.enabled}>
      <div class="row" style="cursor:pointer" role="button" tabindex="0"
        onclick={() => (open = open === r.name ? null : r.name)}
        onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open = open === r.name ? null : r.name } }}>
        <Severity sev={r.severity} />
        <strong>{r.title}</strong>
        <span class="mono small muted">{r.name}</span>
        {#if !r.enabled}<span class="badge">disabled</span>{/if}
        <span class="spacer"></span>
        {#if r.last_error}<span class="badge critical" title={r.last_error}>error</span>{/if}
        <span class="small muted">{r.last_run ? `ran ${fmtAgo(r.last_run)} · ${r.last_findings} found · ${r.last_ms}ms` : 'not run yet'}</span>
        <button class="small" onclick={(e) => { e.stopPropagation(); toggle(r) }}>{r.enabled ? 'Disable' : 'Enable'}</button>
        <button class="small" onclick={(e) => { e.stopPropagation(); run(r) }}>Run now</button>
      </div>
      {#if open === r.name}
        {@const d = draft(r)}
        <div class="body">
          <p class="secondary small">{r.description}</p>
          <div class="row small muted">evaluated every {r.interval} · window {r.window}</div>
          <div class="fields">
            <label>Severity
              <select bind:value={d.severity}><option>info</option><option>warning</option><option>critical</option></select>
            </label>
            {#each r.params as p}
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
        </div>
      {/if}
    </div>
  {/each}
</div>

<style>
  .rule.off { opacity: .7; }
  .body { margin-top: .75rem; border-top: 1px solid var(--border); padding-top: .75rem; }
  .fields { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: .6rem; margin: .5rem 0; }
  label { display: flex; flex-direction: column; gap: .2rem; font-size: .82rem; color: var(--text-secondary); }
  .hint { color: var(--text-muted); font-size: .72rem; }
</style>
