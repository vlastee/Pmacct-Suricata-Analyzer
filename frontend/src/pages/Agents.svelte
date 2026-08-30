<script lang="ts">
  import { api, type Agent, type AgentBuild, type EnrollToken } from '../lib/api'
  import { fmtAgo, fmtTime, fmtNum, fmtBytes } from '../lib/format'
  import Loading from '../lib/components/Loading.svelte'
  import IPLabel from '../lib/components/IPLabel.svelte'

  let { reloadKey }: { reloadKey: number } = $props()
  let items = $state<Agent[]>([])
  let builds = $state<AgentBuild[]>([])
  let tlsRequired = $state(false)
  let error = $state<string | null>(null)
  let msg = $state('')
  let editing = $state<number | null>(null)
  let editName = $state('')
  let editNote = $state('')

  // installer builder
  let os = $state<'linux' | 'windows'>('linux')
  let name = $state('')
  let capture = $state('auto')
  let sendCmdline = $state(false)
  let token = $state<EnrollToken | null>(null)
  let tokenOS = $state<'linux' | 'windows'>('linux')

  async function load() {
    error = null
    try {
      const [a, b] = await Promise.all([api.agents(), api.agentBuilds().catch(() => ({ items: [] as AgentBuild[], dir: '' }))])
      items = a.items; tlsRequired = a.tls_required; builds = b.items
    } catch (e: any) { error = e.message }
  }
  $effect(() => { void reloadKey; load() })
  $effect(() => { const t = setInterval(load, 30000); return () => clearInterval(t) })
  $effect(() => { if (os === 'windows' && capture === 'ebpf') capture = 'auto' })

  let build = $derived(builds.find(b => b.target === (os === 'linux' ? 'linux-amd64' : 'windows-amd64')) ?? null)

  async function generate(e: Event) {
    e.preventDefault(); msg = ''
    try { token = await api.createEnrollToken(name.trim()); tokenOS = os } catch (err: any) { msg = err.message }
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

  // One-liners. Linux: pipe the installer to bash with the parameters; Windows: load the
  // installer function and call it. Both verify the CA fingerprint before trusting anything.
  let oneLiner = $derived.by(() => {
    if (!token) return ''
    const t = token
    const fp = t.ca_fingerprint_sha256 ?? ''
    const pin = t.ca_spki_sha256 ?? ''
    if (tokenOS === 'linux') {
      const flags = [`--server ${t.server_url}`, `--token ${t.enroll_token}`, fp && `--ca-fingerprint ${fp}`, pin && `--ca-pin ${pin}`, `--capture ${capture}`, sendCmdline && '--send-cmdline'].filter(Boolean).join(' ')
      return `curl -sk ${t.server_url}/api/v1/agent/install.sh | sudo bash -s -- ${flags}`
    }
    const args = [`-Server ${t.server_url}`, `-Token ${t.enroll_token}`, fp && `-CaFingerprint ${fp}`, pin && `-CaPin ${pin}`, `-Capture ${capture === 'ebpf' ? 'auto' : capture}`, sendCmdline && '-SendCmdline'].filter(Boolean).join(' ')
    return `[Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }; iex (iwr -UseBasicParsing ${t.server_url}/api/v1/agent/install.ps1).Content; Install-PmacctAgent ${args}`
  })
  let manualEnroll = $derived(token ? `pmacct-agent enroll --server ${token.server_url} --token ${token.enroll_token}${token.ca_spki_sha256 ? ` --ca-pin ${token.ca_spki_sha256}` : ''} --capture ${capture}${sendCmdline ? ' --send-cmdline' : ''}` : '')
</script>

<Loading {error} />
<p class="muted small">Endpoint agents report <b>which program</b> on a machine opened which connection (per minute, per destination), so alerts and host pages can say <i>via chrome.exe (petro)</i>. Windows and Linux for now. {#if !tlsRequired}<span class="badge warning">TLS is off — enable TLS_LISTEN_ADDR before enrolling agents so tokens never cross the LAN in clear.</span>{/if}</p>

<div class="card" style="margin-bottom:1rem">
  <h3>Install an agent</h3>
  <form class="row" onsubmit={generate} style="flex-wrap:wrap; gap:.6rem">
    <label class="row" style="gap:.3rem">target
      <select bind:value={os}><option value="linux">Linux (x86-64)</option><option value="windows">Windows (x86-64)</option></select>
    </label>
    <input placeholder="name (defaults to the machine's hostname)" bind:value={name} size="30" />
    <label class="row" style="gap:.3rem">capture
      <select bind:value={capture}>
        <option value="auto">auto</option><option value="poll">poll</option>
        {#if os === 'linux'}<option value="ebpf">ebpf</option>{/if}
      </select>
    </label>
    <label class="row" style="gap:.3rem"><input type="checkbox" bind:checked={sendCmdline} /> send command lines</label>
    <button type="submit" class="primary">Generate install command</button>
    {#if msg}<span class="small muted">{msg}</span>{/if}
  </form>
  <div class="small muted" style="margin-top:.4rem">
    {#if build}
      binary in this image: <span class="mono">{build.file}</span> · {fmtBytes(build.size)} · built {fmtAgo(build.built)} · sha256 <span class="mono">{build.sha256.slice(0, 16)}…</span>
    {:else}
      <span class="badge warning">no {os} agent binary in this image</span> — rebuild the analyzer image with <span class="mono">WITH_AGENT=1</span> (default) so installers can download it, or copy a locally built binary by hand.
    {/if}
  </div>
  {#if token}
    <div class="small" style="margin-top:.8rem">
      <div><b>{tokenOS === 'linux' ? 'On the Linux machine, in a shell:' : 'On the Windows machine, in an administrator PowerShell:'}</b> <span class="muted">(token is single-use, valid until {fmtTime(token.expires_at)})</span></div>
      <pre class="cmd">{oneLiner}</pre>
      <div class="row" style="gap:.6rem">
        <button class="small" onclick={() => copy(oneLiner)}>copy command</button>
        {#if token.ca_fingerprint_sha256}<span class="muted">verifies CA fingerprint <span class="mono">{token.ca_fingerprint_sha256}</span> before trusting anything</span>{/if}
      </div>
      <details style="margin-top:.5rem"><summary class="muted">what it does / manual steps</summary>
        <div class="muted" style="margin-top:.3rem">
          Downloads the agent from this server (checksum-verified), enrolls it with the token and CA pin, and registers it as a
          {tokenOS === 'linux' ? 'systemd service' : 'Windows service (and imports the CA into the machine\'s trusted roots)'}.
          Manual alternative: download <a href="/api/v1/agent/download/{tokenOS === 'linux' ? 'linux-amd64' : 'windows-amd64'}">the binary</a>, then run
          <span class="mono">{manualEnroll}</span> followed by <span class="mono">pmacct-agent install</span>.
        </div>
      </details>
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
