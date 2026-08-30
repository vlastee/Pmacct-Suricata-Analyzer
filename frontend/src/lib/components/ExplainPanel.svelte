<script lang="ts">
  import { api, type ExplainReport, type KBEntry } from '../api'
  import { fmtAgo, fmtTime, fmtCompact, fmtBytes, flag } from '../format'
  import IPLabel from './IPLabel.svelte'

  let { report, onclose, onchanged }: { report: ExplainReport; onclose: () => void; onchanged?: () => void } = $props()
  const p = $derived(report.program)

  // External look-ups (opened in a new tab; nothing is sent until clicked).
  const base = $derived(p.exe ? (p.exe.split(/[\\/]/).pop() || p.name) : (p.name === '(unknown process)' ? '' : p.name))
  const q = $derived(encodeURIComponent(base + (p.os === 'windows' ? ' process' : ' linux process')))
  const id = $derived(report.program.identity)
  const file = $derived(report.program.file)
  const lol = $derived(report.program.lolbin)
  const vtTotal = $derived(file?.vt ? (file.vt.malicious ?? 0) + (file.vt.suspicious ?? 0) + (file.vt.harmless ?? 0) + (file.vt.undetected ?? 0) : 0)
  const originLabel: Record<string, string> = {
    dpkg: 'Debian/Ubuntu package', apk: 'Alpine package', pacman: 'Arch package', snap: 'Snap', flatpak: 'Flatpak', appimage: 'AppImage', nix: 'Nix store',
    container: 'container image', venv: 'language environment (venv / node_modules / …)', 'user-install': 'user-level install', home: 'home directory', download: 'Downloads folder',
    tmp: 'temporary location', opt: '/opt (manual install)', local: '/usr/local (manual install)', unpackaged: 'no package owns it',
    windows: 'Windows system directory', 'program-files': 'Program Files', store: 'Microsoft Store (MSIX)', programdata: 'ProgramData',
  }
  let links = $derived([
    ...(lol ? [{ label: lol.source === 'lolbas' ? 'LOLBAS entry' : 'GTFOBins entry', href: lol.url }] : []),
    { label: 'Google', href: `https://www.google.com/search?q=${q}` },
    { label: 'DuckDuckGo', href: `https://duckduckgo.com/?q=${q}` },
    { label: 'VirusTotal', href: p.hashes.length ? `https://www.virustotal.com/gui/file/${p.hashes[0]}` : `https://www.virustotal.com/gui/search/${encodeURIComponent(base)}` },
    { label: 'GitHub code', href: `https://github.com/search?q=${encodeURIComponent('"' + base + '"')}&type=code` },
    ...(p.os === 'windows' ? [{ label: 'file.net', href: `https://www.file.net/process/${encodeURIComponent(base.toLowerCase())}.html` }] : []),
  ])

  // Knowledge-base editor (pre-filled from the program; edits the matching user entry).
  let editing = $state(false)
  let kbMsg = $state('')
  let draft = $state({ match_kind: 'path' as 'name' | 'path' | 'hash', pattern: '', title: '', category: '', description: '', expected: '', verify: '', risk: '', note: '' })
  function startEdit() {
    const k = p.known
    const fromUser = p.known_source === 'user' && k
    draft = {
      match_kind: fromUser ? draft.match_kind : p.exe ? 'path' : 'name',
      pattern: fromUser ? draft.pattern : (p.exe || p.name),
      title: k?.title ?? base, category: k?.category ?? '', description: k?.description ?? '', expected: k?.expected ?? '',
      verify: (k?.verify ?? []).join('\n'), risk: k?.risk ?? '', note: '',
    }
    if (fromUser) { api.kb().then(r => { const e = r.items.find(x => x.id === p.known_id); if (e) draft = { ...draft, match_kind: e.match_kind, pattern: e.pattern, note: e.note } }).catch(() => {}) }
    editing = true; kbMsg = ''
  }
  async function saveKB() {
    kbMsg = 'saving…'
    try {
      await api.upsertKB({ ...draft, verify: draft.verify.split('\n').map(s => s.trim()).filter(Boolean) })
      kbMsg = 'saved — Explain will use this entry from now on'; editing = false; onchanged?.()
    } catch (e: any) { kbMsg = e.message }
  }
  async function deleteKB() {
    if (!p.known_id || !confirm('Remove this knowledge-base entry?')) return
    try { await api.deleteKB(p.known_id); kbMsg = 'entry removed'; onchanged?.() } catch (e: any) { kbMsg = e.message }
  }
  const badge = (level: string) => (level === 'suspicious' || level === 'critical' ? 'critical' : level === 'review' || level === 'warn' ? 'warning' : 'good')
  let copied = $state(false)
  function copyVerify() { navigator.clipboard?.writeText(report.verify.join('\n')).catch(() => {}); copied = true; setTimeout(() => (copied = false), 1500) }
</script>

<div class="card explain">
  <div class="row">
    <h3 style="margin:0">Explain: {p.name}{#if p.container} <span class="muted">→ {p.container}</span>{/if}</h3>
    <span class="badge {badge(report.assessment.level)}">{report.assessment.level}</span>
    <span class="small">{report.assessment.summary}</span>
    <span class="spacer"></span>
    <span class="small muted">{p.machine ? p.machine + ' · ' : ''}{fmtTime(report.window.Since)} → {fmtTime(report.window.Until)}</span>
    <button class="x" onclick={onclose} title="Close">×</button>
  </div>

  <div class="grid cols-2" style="margin-top:.6rem">
    <div>
      <h4>What it is
        {#if p.known_source === 'user'}<span class="badge good" title="from your knowledge base">yours</span>
        {:else if p.known_source === 'lolbas' || p.known_source === 'gtfobins'}<span class="badge warning" title="from the {p.known_source === 'lolbas' ? 'LOLBAS' : 'GTFOBins'} catalogue">{p.known_source === 'lolbas' ? 'LOLBAS' : 'GTFOBins'}</span>{/if}
        {#if base}<button class="small" onclick={startEdit}>{p.known_source === 'user' ? 'Edit entry' : p.known ? 'Override in knowledge base' : 'Add to knowledge base'}</button>{/if}
        {#if p.known_source === 'user'}<button class="small" onclick={deleteKB}>Remove</button>{/if}
      </h4>
      {#if p.known}
        <div><b>{p.known.title}</b> {#if p.known.category}<span class="badge">{p.known.category}</span>{/if}</div>
        <p class="small">{p.known.description}</p>
        {#if p.known.expected}<p class="small muted"><b>Normally talks to:</b> {p.known.expected}</p>{/if}
      {:else if base}
        <p class="small muted">Not in the knowledge base — judge it by its path, hash and destinations, or add what you know.</p>
      {:else}
        <p class="small muted">Connections the agent could not attribute to a process — see the signal on the right; the destinations below are still real.</p>
      {/if}
      {#if base}
        <div class="row small" style="gap:.5rem; margin:.2rem 0 .4rem"><span class="muted">look up:</span>
          {#each links as l (l.label)}<a href={l.href} target="_blank" rel="noopener">{l.label} ↗</a>{/each}
        </div>
      {/if}
      {#if editing}
        <div class="kb">
          <div class="fields">
            <label>match by
              <select bind:value={draft.match_kind}><option value="path">executable path (glob)</option><option value="name">program name (glob)</option><option value="hash">SHA-256</option></select>
            </label>
            <label class="span2">pattern <input bind:value={draft.pattern} placeholder="/opt/app/*/server · pmacct-* · <sha256>" /><span class="hint">* and ? are wildcards; case-insensitive</span></label>
            <label>title <input bind:value={draft.title} /></label>
            <label>category <input bind:value={draft.category} placeholder="browser, updater, house-app…" /></label>
            <label class="span2">description <input bind:value={draft.description} placeholder="what it is" /></label>
            <label class="span2">normally talks to <input bind:value={draft.expected} placeholder="expected destinations" /></label>
            <label class="span2">verify commands (one per line) <textarea rows="2" bind:value={draft.verify}></textarea></label>
            <label>risk
              <select bind:value={draft.risk}><option value="">none</option><option value="interpreter">interpreter (identity = script)</option><option value="lolbin">abusable utility</option><option value="no-network">must never talk out</option></select>
            </label>
            <label>note <input bind:value={draft.note} placeholder="private note" /></label>
          </div>
          <div class="row"><button class="primary small" onclick={saveKB}>Save</button><button class="small" onclick={() => (editing = false)}>Cancel</button></div>
        </div>
      {/if}
      {#if kbMsg}<div class="small muted">{kbMsg}</div>{/if}
      <dl class="small">
        <dt>Executable</dt><dd class="mono" style="word-break:break-all">{p.exe || '–'}</dd>
        <dt>User</dt><dd>{p.user || '–'}{#if p.os} · {p.os}{/if}</dd>
        {#if p.cmdline}<dt>Command line</dt><dd class="mono" style="word-break:break-all">{p.cmdline}</dd>{/if}
        <dt>SHA-256</dt><dd class="mono" style="word-break:break-all">{p.hashes.length ? p.hashes.join(', ') : id?.sha256 ?? 'not available'}</dd>
        {#if id}
          <dt>Origin</dt>
          <dd>
            {originLabel[id.origin ?? ''] ?? id.origin ?? 'not determined'}{#if id.package} · <b>{id.package}</b>{#if id.package_version} {id.package_version}{/if}{/if}
            {#if id.verified === true}<span class="badge good" title="the file's digest matches the package manifest">matches manifest</span>
            {:else if id.verified === false}<span class="badge critical" title="the file's digest differs from the package manifest">MODIFIED</span>{/if}
            {#if id.note}<span class="muted"> · {id.note}</span>{/if}
          </dd>
          {#if id.signature}
            <dt>Signature</dt>
            <dd>
              <span class="badge {id.signature === 'valid' ? 'good' : id.signature === 'invalid' ? 'critical' : 'warning'}">{id.signature}</span>
              {#if id.signer} {id.signer}{/if}
            </dd>
          {/if}
          {#if id.company || id.product || id.file_version || id.description}
            <dt>Version info</dt><dd>{[id.company, id.product, id.file_version].filter(Boolean).join(' · ')}{#if id.description} <span class="muted">— {id.description}</span>{/if}</dd>
          {/if}
          <dt>File</dt><dd class="muted">{fmtBytes(id.size)}{#if id.modified} · written {fmtTime(id.modified)}{/if} · reported {fmtAgo(id.last_reported)}</dd>
        {:else if p.os}
          <dt>Origin</dt><dd class="muted">not reported — agent 0.3+ adds the owning package / signer for every program</dd>
        {/if}
        {#if file}
          <dt>VirusTotal file</dt>
          <dd>
            {#if file.vt.status === 'ok'}
              <span class="badge {(file.vt.malicious ?? 0) >= 3 ? 'critical' : (file.vt.malicious ?? 0) > 0 ? 'warning' : 'good'}">{file.vt.malicious ?? 0} / {vtTotal} engines</span>
              {#if file.vt.label} <b>{file.vt.label}</b>{/if}
              {#if file.vt.names.length} <span class="muted">known as {file.vt.names.slice(0, 3).join(', ')}</span>{/if}
              {#if file.vt.signers.length} <span class="muted">· signed by {file.vt.signers[0]}</span>{/if}
              {#if file.vt.first_seen} <span class="muted">· first submitted {fmtTime(file.vt.first_seen)}</span>{/if}
            {:else if file.vt.status === 'unknown'}<span class="badge warning">never submitted</span> <span class="muted">no other party has seen this exact file</span>
            {:else if file.vt.status === 'failed'}<span class="badge">look-up failed</span> <span class="muted">{file.vt.error ?? ''}</span>
            {:else}<span class="muted">pending — looked up in the next enrichment pass{p.hashes.length || id ? '' : ' (needs a hash)'}</span>{/if}
            {#if file.sha256}<a href={`https://www.virustotal.com/gui/file/${file.sha256}`} target="_blank" rel="noopener" style="margin-left:.4rem">open ↗</a>{/if}
          </dd>
          <dt>Cymru MHR</dt>
          <dd>
            {#if file.mhr.status === 'listed'}<span class="badge critical">known malware</span> <span class="muted">{file.mhr.detection ?? '?'}% of AV engines detect it{#if file.mhr.last_seen} · last seen {fmtTime(file.mhr.last_seen)}{/if}</span>
            {:else if file.mhr.status === 'clean'}<span class="badge good">not listed</span>
            {:else if file.mhr.status === 'failed'}<span class="badge">look-up failed</span>
            {:else if file.mhr.status === 'skipped'}<span class="muted">needs an MD5/SHA-1 (agent 0.3+)</span>
            {:else}<span class="muted">pending</span>{/if}
          </dd>
        {/if}
        {#if lol}
          <dt>{lol.source === 'lolbas' ? 'LOLBAS' : 'GTFOBins'}</dt>
          <dd><span class="badge warning">listed</span> abusable for {lol.functions.join(', ')}{#if lol.mitre.length} <span class="muted mono">· {lol.mitre.join(' ')}</span>{/if} <a href={lol.url} target="_blank" rel="noopener">entry ↗</a></dd>
        {/if}
        <dt>Seen</dt><dd>first {p.first_seen ? fmtTime(p.first_seen) : '–'} · last {p.last_seen ? fmtAgo(p.last_seen) : '–'} · {fmtCompact(p.conns)} connections to {p.destinations} destinations in this window</dd>
        <dt>Addresses</dt><dd class="mono">{p.hosts.join(', ') || '–'}{#if p.pids.length} · pids {p.pids.join(', ')}{/if}</dd>
      </dl>
    </div>
    <div>
      <h4>Signals</h4>
      <ul class="signals small">
        {#each report.signals as s, i (i)}
          <li><span class="badge {badge(s.level)}">{s.level}</span> {s.text}</li>
        {/each}
      </ul>
      <h4 style="margin-top:.6rem">Verify on the machine <button class="small" onclick={copyVerify}>{copied ? 'copied' : 'copy'}</button></h4>
      <pre class="cmd">{report.verify.join('\n')}</pre>
    </div>
  </div>

  <h4 style="margin-top:.8rem">Destinations <span class="muted">· {report.destinations.length}</span></h4>
  <div class="overflow"><table>
    <thead><tr><th>Destination</th><th class="num">Port</th><th>Network</th><th>Reputation</th><th>Who else uses it</th><th class="num">Conns</th><th>Timing</th></tr></thead>
    <tbody>
      {#each report.destinations as d (d.dst + ':' + d.port + d.proto)}
        <tr>
          <td>
            <IPLabel ip={d.dst} />
            <div class="small muted mono">{d.hostname || d.names[0] || 'no reverse DNS'}{#if d.names.length && d.hostname && d.names[0] !== d.hostname} · {d.names[0]}{/if}{#if d.flags.includes('rdns-live')} <span title="looked up live">(live)</span>{/if}</div>
          </td>
          <td class="num mono">{d.port}<div class="small muted">{d.proto}{d.service ? ' ' + d.service : ''}</div></td>
          <td class="small">
            <div><b>{d.infra.label}</b>{#if d.country} {flag(d.country)}{/if}{#if d.asn} <span class="muted mono">{d.asn}</span>{/if}</div>
            <div class="muted" style="max-width:320px">{d.org || ''}{d.hosting ? ' · hosting' : ''}{d.proxy ? ' · proxy' : ''}</div>
            <div class="muted" style="max-width:320px">{d.infra.note}</div>
          </td>
          <td class="small">
            {#if d.trusted}<span class="badge good" title="trusted list: {d.trusted}">trusted</span>{/if}
            {#if d.lists.length}<span class="badge critical">listed: {d.lists.join(', ')}</span>{/if}
            {#if d.vt_malicious}<span class="badge critical">VT {d.vt_malicious} malicious</span>{/if}
            {#each d.reputation as r}<span class="badge warning">{r}</span>{/each}
            {#if d.open_alerts}<div class="muted">{d.open_alerts} open alert(s): {d.alert_titles.join('; ')}</div>{/if}
            {#if d.ids_events}<div class="muted">{d.ids_events} Suricata event(s)</div>{/if}
            {#if d.notes}<div class="muted">{d.notes} note(s)</div>{/if}
            {#if !d.trusted && !d.lists.length && !d.vt_malicious && !d.reputation.length && !d.open_alerts && !d.ids_events}<span class="muted">clean</span>{/if}
          </td>
          <td class="small">
            {#if d.other_program_count || d.other_hosts}
              {#if d.other_hosts}<div>{d.other_hosts} other host(s)</div>{/if}
              {#if d.other_program_count}<div class="muted">{d.other_program_count} other program(s): {d.other_programs.join(', ')}</div>{/if}
            {:else}<span class="badge warning" title="no other host or program talks to it">only this program</span>{/if}
          </td>
          <td class="num">{fmtCompact(d.conns)}{#if d.bytes}<div class="small muted">{fmtBytes(d.bytes)}</div>{/if}</td>
          <td class="small">
            <div>{fmtAgo(d.first)} → {fmtAgo(d.last)}</div>
            {#if d.beacon}<span class="badge warning" title="{d.beacon.contacts} contacts, gap CV {d.beacon.gap_cv}">every ~{d.beacon.avg_gap_min} min</span>{/if}
          </td>
        </tr>
      {:else}<tr><td colspan="7" class="empty">No destinations in this window</td></tr>{/each}
    </tbody>
  </table></div>
</div>

<style>
  /* The panel is rendered inside table rows whose cells default to nowrap: reset it here and
     keep only numeric cells on one line. */
  .explain { margin-top: .8rem; border-color: rgba(57,135,229,.4); white-space: normal; min-width: 0; }
  .explain :global(td), .explain :global(th) { white-space: normal; vertical-align: top; }
  .explain :global(td.num), .explain :global(th.num) { white-space: nowrap; }
  .explain p { margin: .3rem 0; }
  .explain .grid { min-width: 0; }
  .explain .grid > div { min-width: 0; }
  h4 { margin: .2rem 0 .3rem; font-size: .9rem; color: var(--text-secondary); }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: .15rem .6rem; margin: .4rem 0 0; }
  dt { color: var(--text-muted); }
  dd { margin: 0; }
  .signals { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: .3rem; }
  .cmd { white-space: pre-wrap; word-break: break-all; background: var(--surface-2); padding: .5rem; border-radius: var(--radius); font-size: .78rem; margin: .2rem 0 0; }
  .x { border: 0; background: transparent; color: inherit; cursor: pointer; padding: 0 .3rem; font-size: 1.1rem; }
  .kb { border: 1px solid var(--border); border-radius: var(--radius); padding: .5rem; margin: .3rem 0; }
  .fields { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: .4rem; margin-bottom: .4rem; }
  .fields label { display: flex; flex-direction: column; gap: .15rem; font-size: .78rem; color: var(--text-secondary); }
  .fields .span2 { grid-column: span 2; }
  .hint { color: var(--text-muted); font-size: .7rem; }
  textarea { font: inherit; background: var(--surface-2); color: inherit; border: 1px solid var(--border); border-radius: var(--radius); padding: .3rem; }
</style>
