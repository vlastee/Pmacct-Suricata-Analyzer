<script lang="ts">
  import type { ExplainReport } from '../api'
  import { fmtAgo, fmtTime, fmtCompact, fmtBytes, flag } from '../format'
  import IPLabel from './IPLabel.svelte'

  let { report, onclose }: { report: ExplainReport; onclose: () => void } = $props()
  const p = $derived(report.program)
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
      <h4>What it is</h4>
      {#if p.known}
        <div><b>{p.known.title}</b> <span class="badge">{p.known.category}</span></div>
        <p class="small">{p.known.description}</p>
        <p class="small muted"><b>Normally talks to:</b> {p.known.expected}</p>
      {:else}
        <p class="small muted">Not in the knowledge base — judge it by its path, hash and destinations.</p>
      {/if}
      <dl class="small">
        <dt>Executable</dt><dd class="mono" style="word-break:break-all">{p.exe || '–'}</dd>
        <dt>User</dt><dd>{p.user || '–'}{#if p.os} · {p.os}{/if}</dd>
        {#if p.cmdline}<dt>Command line</dt><dd class="mono" style="word-break:break-all">{p.cmdline}</dd>{/if}
        <dt>SHA-256</dt><dd class="mono" style="word-break:break-all">{p.hashes.length ? p.hashes.join(', ') : 'not available'}</dd>
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
  .explain { margin-top: .8rem; border-color: rgba(57,135,229,.4); }
  h4 { margin: .2rem 0 .3rem; font-size: .9rem; color: var(--text-secondary); }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: .15rem .6rem; margin: .4rem 0 0; }
  dt { color: var(--text-muted); }
  dd { margin: 0; }
  .signals { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: .3rem; }
  .cmd { white-space: pre-wrap; word-break: break-all; background: var(--surface-2); padding: .5rem; border-radius: var(--radius); font-size: .78rem; margin: .2rem 0 0; }
  .x { border: 0; background: transparent; color: inherit; cursor: pointer; padding: 0 .3rem; font-size: 1.1rem; }
</style>
