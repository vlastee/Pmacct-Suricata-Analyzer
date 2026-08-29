<script lang="ts">
  import { api, type LoginActivity, type AttemptStat, type IPRule, type AuthUser } from '../lib/api'
  import { auth } from '../lib/auth.svelte'
  import { fmtTime, fmtAgo } from '../lib/format'
  import Loading from '../lib/components/Loading.svelte'

  let { reloadKey }: { reloadKey: number } = $props()
  let activity = $state<LoginActivity[]>([])
  let attackers = $state<AttemptStat[]>([])
  let rules = $state<IPRule[]>([])
  let users = $state<AuthUser[]>([])
  let allowlistOnly = $state(false)
  let error = $state<string | null>(null)
  let msg = $state('')

  let filterIP = $state('')
  let filterUser = $state('')
  let onlyFailures = $state(false)

  // add-rule form
  let ruleNet = $state(''), ruleAction = $state<'deny' | 'allow'>('deny'), ruleNote = $state('')
  // add-user form
  let newUser = $state(''), newPass = $state(''), newAdmin = $state(false)

  async function load() {
    error = null
    try {
      const [act, att, rl, us] = await Promise.all([
        api.securityActivity({ ip: filterIP || undefined, user: filterUser || undefined, failures: onlyFailures }),
        api.securityAttackers(), api.ipRules(), api.users(),
      ])
      activity = act.items; attackers = att.items; rules = rl.items; allowlistOnly = rl.allowlist_only; users = us.items
    } catch (e: any) { error = e.message }
  }
  $effect(() => { void reloadKey; load() })

  async function block(ip: string) { try { await api.addIPRule(ip, 'deny', 'blocked from Security'); await load() } catch (e: any) { msg = e.message } }
  async function removeRule(net: string) { try { await api.deleteIPRule(net); await load() } catch (e: any) { msg = e.message } }
  async function addRule(e: Event) {
    e.preventDefault(); msg = ''
    try { await api.addIPRule(ruleNet.trim(), ruleAction, ruleNote.trim()); ruleNet = ''; ruleNote = ''; await load() } catch (er: any) { msg = er.message }
  }
  async function addUser(e: Event) {
    e.preventDefault(); msg = ''
    try { await api.createUser(newUser.trim(), newPass, newAdmin); newUser = ''; newPass = ''; newAdmin = false; msg = 'user created (must set password on first login)'; await load() }
    catch (er: any) { msg = er.message }
  }
  async function userAction(u: AuthUser, action: 'disable' | 'enable' | 'reset') {
    try {
      if (action === 'reset') {
        const p = prompt(`New temporary password for ${u.username} (they must change it on next login):`)
        if (!p) return
        await api.userAction(u.id, 'reset', p)
        msg = `password reset for ${u.username}`
      } else await api.userAction(u.id, action)
      await load()
    } catch (e: any) { msg = e.message }
  }
  async function removeUser(u: AuthUser) {
    if (!confirm(`Delete user ${u.username}?`)) return
    try { await api.deleteUser(u.id); await load() } catch (e: any) { msg = e.message }
  }
</script>

<Loading {error} />
{#if msg}<div class="card small" style="margin-bottom:1rem">{msg}</div>{/if}

<div class="grid cols-2">
  <div class="card overflow">
    <h3>Recent login attempts by IP (24h)</h3>
    <table>
      <thead><tr><th>IP</th><th class="num">Failures</th><th class="num">OK</th><th class="num">Last</th><th>Status</th><th></th></tr></thead>
      <tbody>
        {#each attackers as a (a.ip)}
          <tr class:bad={a.failures > 0 && a.successes === 0}>
            <td class="mono">{a.ip}</td>
            <td class="num">{a.failures}</td><td class="num">{a.successes}</td>
            <td class="num small">{fmtAgo(a.last_seen)}</td>
            <td>{#if a.blocked}<span class="badge critical">blocked{#if a.blocked_until} · {fmtAgo(a.blocked_until)}{/if}</span>{:else}<span class="muted small">–</span>{/if}</td>
            <td class="num">{#if !a.blocked}<button class="small" onclick={() => block(a.ip)}>Block</button>{/if}</td>
          </tr>
        {:else}<tr><td colspan="6" class="empty">No login attempts</td></tr>{/each}
      </tbody>
    </table>
  </div>

  <div class="card overflow">
    <h3>IP access rules {#if allowlistOnly}<span class="badge warning">allowlist-only mode</span>{/if}</h3>
    <form class="row" style="margin-bottom:.6rem" onsubmit={addRule}>
      <input placeholder="IP or CIDR" bind:value={ruleNet} size="18" required />
      <select bind:value={ruleAction}><option value="deny">deny</option><option value="allow">allow</option></select>
      <input placeholder="note" bind:value={ruleNote} size="16" />
      <button class="primary" type="submit">Add</button>
    </form>
    <table>
      <thead><tr><th>Network</th><th>Action</th><th>Source</th><th>Note</th><th class="num">Expires</th><th></th></tr></thead>
      <tbody>
        {#each rules as r (r.net)}
          <tr>
            <td class="mono">{r.net}</td>
            <td><span class="badge {r.action === 'deny' ? 'critical' : 'good'}">{r.action}</span></td>
            <td class="small">{r.source}</td>
            <td class="small secondary">{r.note ?? ''}</td>
            <td class="num small">{r.expires_at ? fmtAgo(r.expires_at) : 'never'}</td>
            <td class="num"><button class="small" onclick={() => removeRule(r.net)}>Remove</button></td>
          </tr>
        {:else}<tr><td colspan="6" class="empty">No rules — auto lockouts from brute-force appear here.</td></tr>{/each}
      </tbody>
    </table>
  </div>
</div>

<div class="card overflow" style="margin-top:1rem">
  <form class="row" style="margin-bottom:.6rem" onsubmit={(e) => { e.preventDefault(); load() }}>
    <h3 style="margin:0">Login activity</h3>
    <span class="spacer"></span>
    <input placeholder="filter IP" bind:value={filterIP} size="16" />
    <input placeholder="filter user" bind:value={filterUser} size="14" />
    <label class="small muted"><input type="checkbox" bind:checked={onlyFailures} /> failures only</label>
    <button type="submit">Apply</button>
  </form>
  <table>
    <thead><tr><th>Time</th><th>IP</th><th>User</th><th>Result</th><th>Reason</th><th>User agent</th></tr></thead>
    <tbody>
      {#each activity as a}
        <tr>
          <td class="small">{fmtTime(a.ts)}</td>
          <td class="mono">{a.ip ?? '–'}</td>
          <td>{a.username ?? '–'}</td>
          <td><span class="badge {a.success ? 'good' : 'critical'}">{a.success ? 'success' : 'fail'}</span></td>
          <td class="small">{a.reason ?? ''}</td>
          <td class="small muted" style="max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{a.user_agent ?? ''}</td>
        </tr>
      {:else}<tr><td colspan="6" class="empty">No activity</td></tr>{/each}
    </tbody>
  </table>
</div>

<div class="card overflow" style="margin-top:1rem">
  <h3>Users</h3>
  <form class="row" style="margin-bottom:.6rem" onsubmit={addUser}>
    <input placeholder="username" bind:value={newUser} size="16" required />
    <input type="password" placeholder="temp password (min 8)" bind:value={newPass} size="20" minlength="8" required />
    <label class="small muted"><input type="checkbox" bind:checked={newAdmin} /> admin</label>
    <button class="primary" type="submit">Add user</button>
  </form>
  <table>
    <thead><tr><th>Username</th><th>Admin</th><th>Status</th><th class="num">Last login</th><th>From</th><th></th></tr></thead>
    <tbody>
      {#each users as u (u.id)}
        <tr>
          <td><strong>{u.username}</strong>{#if auth.user && auth.user.id === u.id}<span class="badge">you</span>{/if}</td>
          <td>{#if u.is_admin}<span class="badge">admin</span>{/if}</td>
          <td>{#if u.disabled}<span class="badge critical">disabled</span>{:else if u.must_change_password}<span class="badge warning">must change pw</span>{:else}<span class="badge good">active</span>{/if}</td>
          <td class="num small">{u.last_login ? fmtAgo(u.last_login) : 'never'}</td>
          <td class="mono small">{u.last_login_ip ?? '–'}</td>
          <td class="num">
            <button class="small" onclick={() => userAction(u, 'reset')}>Reset pw</button>
            {#if auth.user && auth.user.id !== u.id}
              {#if u.disabled}<button class="small" onclick={() => userAction(u, 'enable')}>Enable</button>
              {:else}<button class="small" onclick={() => userAction(u, 'disable')}>Disable</button>{/if}
              <button class="small" onclick={() => removeUser(u)}>Delete</button>
            {/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  tr.bad td { background: rgba(230,103,103,.06); }
</style>
