<script lang="ts">
  import { api, type Agent, type EnrollToken } from '../lib/api'
  import { fmtAgo, fmtTime, fmtNum } from '../lib/format'
  import Loading from '../lib/components/Loading.svelte'
  import IPLabel from '../lib/components/IPLabel.svelte'

  let { reloadKey }: { reloadKey: number } = $props()
  let items = $state<Agent[]>([])
  let tlsRequired = $state(false)
  let error = $state<string | null>(null)
  let msg = $state('')
  let newName = $state('')
  let token = $state<EnrollToken | null>(null)
  let editing = $state<number | null>(null)
  let editName = $state('')
  let editNote = $state('')

  async function load() {
    error = null
    try { const r = await api.agents(); items = r.items; tlsRequired = r.tls_required } catch (e: any) { error = e.message }
  }
  $effect(() => { void reloadKey; load() })
  $effect(() => { const t = setInterval(load, 30000); return () => clearInterval(t) })

  async function mint(e: Event) {
    e.preventDefault(); msg = ''
    try { token = await api.createEnrollToken(newName.trim()); newName = '' } catch (err: any) { msg = err.message }
  }
  function copy(text: string) { navigator.clipboard?.writeText(text).catch(() => {}); msg = 'copied' }
  function online(a: Agent) { return !a.revoked_at && a.last_seen && Date.now() - new Date(a.last_seen).getTime() < 5 * 60 * 1000 }
  async function revoke(a: Agent) {
    if (!confirm(`Revoke "${a.name}"? Its token stops working; reported data is kept.`)) return
    try { await api.revokeAgent(a.id); await load() } catch (err: any) { msg = err.message }
  }
  async function del(a: Agent) {
    if (!confirm(`Delete "${a.name}" and everything it reported?`)) return
    try { await api.deleteAgent(a.id); await load() } catch (err: any) { msg = err.message }
  }
  async function save(a: Agent) {
    try { await api.updateAgent(a.id, editName, editNote); editing = null; await load() } catch (err: any) { msg = err.message }
  }
  let enrollCmd = $derived(token
    ? `pmacct-agent enroll --server ${token.server_url} --token ${token.enroll_token}${token.ca_spki_sha256 ? ` --ca-pin ${token.ca_spki_sha256}` : ''}`
    : '')
</script>

<Loading {error} />
<p class="muted small">Endpoint agents report <b>which program</b> on a machine opened which connection (per minute, per destination), so alerts and host pages can say <i>via chrome.exe (petro)</i>. Windows and Linux for now. {#if !tlsRequired}<span class="badge warning">TLS is off — enable TLS_LISTEN_ADDR before enrolling agents so tokens never cross the LAN in clear.</span>{/if}</p>

<div class="card" style="margin-bottom:1rem">
  <h3>Enroll a new agent</h3>
  <form class="row" onsubmit={mint}>
    <input placeholder="name (defaults to the machine's hostname)" bind:value={newName} size="36" />
    <button type="submit" class="primary">Create enrollment token</button>
    {#if msg}<span class="small muted">{msg}</span>{/if}
  </form>
  {#if token}
    <div class="small" style="margin-top:.6rem">
      <div>Single-use, valid until {fmtTime(token.expires_at)}. Run this on the machine (as administrator / root):</div>
      <pre class="cmd">{enrollCmd}</pre>
      <div class="row"><button class="small" onclick={() => copy(enrollCmd)}>copy command</button>
        {#if token.ca_fingerprint_sha256}<span class="muted">CA fingerprint <span class="mono">{token.ca_fingerprint_sha256}</span></span>{/if}</div>
      <div class="muted" style="margin-top:.4rem">Then <span class="mono">pmacct-agent install</span> registers it as a service (systemd / Windows service) and starts it. The agent pins the CA it fetched at enrollment; the pin above lets you verify it.</div>
    </div>
  {/if}
</div>

<div class="card overflow">
  <h3>Agents <span class="muted">· {items.length}</span></h3>
  <table>
    <thead><tr><th>Name</th><th>Host</th><th>Addresses</th><th>OS</th><th>Version</th><th>Capture</th><th class="num">Events</th><th class="num">Last batch</th><th class="num">Dropped</th><th>Last seen</th><th></th></tr></thead>
    <tbody>
      {#each items as a (a.id)}
        <tr class:off={!!a.revoked_at}>
          <td>
            {#if editing === a.id}
              <input bind:value={editName} size="14" /> <input bind:value={editNote} placeholder="note" size="18" />
              <button class="small" onclick={() => save(a)}>Save</button><button class="small" onclick={() => (editing = null)}>Cancel</button>
            {:else}
              <span class="badge {online(a) ? 'good' : a.revoked_at ? '' : 'warning'}" title={a.revoked_at ? 'revoked ' + fmtTime(a.revoked_at) : online(a) ? 'reporting' : 'silent for more than 5 minutes'}>{a.revoked_at ? 'revoked' : online(a) ? 'online' : 'silent'}</span>
              <strong>{a.name}</strong>{#if a.note} <span class="small muted">— {a.note}</span>{/if}
            {/if}
          </td>
          <td class="mono small">{a.hostname}</td>
          <td>{#each a.ips as ip (ip)}<div><IPLabel {ip} local={true} /></div>{/each}</td>
          <td class="small">{a.os}/{a.arch}</td>
          <td class="small mono">{a.version}</td>
          <td class="small">{a.capture || '–'}</td>
          <td class="num">{fmtNum(a.events_total)}</td>
          <td class="num">{a.last_batch}</td>
          <td class="num" class:warn={a.dropped > 0}>{fmtNum(a.dropped)}</td>
          <td class="small" title={a.last_seen ? fmtTime(a.last_seen) : ''}>{a.last_seen ? fmtAgo(a.last_seen) : 'never'}{#if a.last_ip} <span class="muted mono">from {a.last_ip}</span>{/if}</td>
          <td class="num actions">
            <button class="small" onclick={() => { editing = a.id; editName = a.name; editNote = a.note }}>Edit</button>
            {#if !a.revoked_at}<button class="small" onclick={() => revoke(a)}>Revoke</button>{/if}
            <button class="small" onclick={() => del(a)}>Delete</button>
          </td>
        </tr>
      {:else}<tr><td colspan="11" class="empty">No agents enrolled yet.</td></tr>{/each}
    </tbody>
  </table>
</div>

<style>
  .cmd { white-space: pre-wrap; word-break: break-all; background: var(--surface-2); padding: .5rem; border-radius: var(--radius); font-size: .8rem; margin: .4rem 0; }
  tr.off { opacity: .6; }
  .warn { color: #f0c56b; }
  .actions button { margin-left: .25rem; }
</style>
