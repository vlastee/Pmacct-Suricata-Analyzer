<script lang="ts">
  import { router } from './lib/router.svelte'
  import { api, type Meta, type AlertSummary } from './lib/api'
  import { fmtTime } from './lib/format'
  import TimeRange from './lib/components/TimeRange.svelte'
  import Overview from './pages/Overview.svelte'
  import Hosts from './pages/Hosts.svelte'
  import HostDetail from './pages/HostDetail.svelte'
  import Flows from './pages/Flows.svelte'
  import Threats from './pages/Threats.svelte'
  import Enrichment from './pages/Enrichment.svelte'
  import Nicknames from './pages/Nicknames.svelte'
  import Alerts from './pages/Alerts.svelte'
  import Rules from './pages/Rules.svelte'
  import IDS from './pages/IDS.svelte'
  import Security from './pages/Security.svelte'
  import Login from './pages/Login.svelte'
  import ChangePassword from './pages/ChangePassword.svelte'
  import { auth } from './lib/auth.svelte'
  import { exclusions } from './lib/exclusions.svelte'

  let reloadKey = $state(0)
  let meta = $state<Meta | null>(null)
  let alerts = $state<AlertSummary | null>(null)
  let menuOpen = $state(false)
  let showChangePw = $state(false)

  auth.refresh()
  $effect(() => {
    if (!auth.authed) return
    api.meta().then(m => (meta = m)).catch(() => {})
    exclusions.refresh()
  })
  async function loadAlerts() { if (!auth.authed) return; try { alerts = await api.alertSummary() } catch {} }
  $effect(() => { void reloadKey; loadAlerts() })
  $effect(() => { const poll = setInterval(loadAlerts, 60000); return () => clearInterval(poll) })
  let activeAlerts = $derived(alerts ? alerts.open + alerts.acked : 0)

  const nav = [
    { path: '/', label: 'Overview' }, { path: '/alerts', label: 'Alerts' }, { path: '/hosts', label: 'Hosts' },
    { path: '/flows', label: 'Flows' }, { path: '/threats', label: 'Threats' }, { path: '/ids', label: 'IDS' },
    { path: '/rules', label: 'Rules' }, { path: '/nicknames', label: 'Nicknames' }, { path: '/enrichment', label: 'Enrichment' },
  ]
  let navItems = $derived(auth.user?.is_admin || auth.authDisabled ? [...nav, { path: '/security', label: 'Security' }] : nav)
  let parts = $derived(router.route.parts)
  let section = $derived(parts[0] ?? '')
</script>

{#if auth.loading}
  <div class="boot">Loading…</div>
{:else if !auth.authDisabled && auth.user === null}
  <Login />
{:else if auth.mustChange}
  <ChangePassword forced={true} />
{:else}

<header>
  <div class="brand"><span class="logo">▲</span> Pmacct Analyzer</div>
  <nav>
    {#each navItems as n}
      <a href={router.href(n.path)} class:active={router.route.path === n.path || (n.path !== '/' && router.route.path.startsWith(n.path))}>{n.label}{#if n.path === '/alerts' && activeAlerts > 0}<span class="navbadge" class:crit={alerts && alerts.critical > 0}>{activeAlerts}</span>{/if}</a>
    {/each}
  </nav>
  <span class="spacer"></span>
  {#if section !== 'enrichment' && section !== 'nicknames' && section !== 'rules' && section !== 'security'}<TimeRange onrefresh={() => reloadKey++} />{/if}
  {#if !auth.authDisabled && auth.user}
    <div class="usermenu">
      <button class="userbtn" onclick={() => (menuOpen = !menuOpen)}>{auth.user.username} ▾</button>
      {#if menuOpen}
        <div class="menu" role="menu">
          <button onclick={() => { showChangePw = true; menuOpen = false }}>Change password</button>
          <button onclick={() => { menuOpen = false; auth.logout() }}>Sign out</button>
        </div>
      {/if}
    </div>
  {/if}
</header>

<main>
  {#if section === '' }
    <Overview {reloadKey} />
  {:else if section === 'hosts' && parts[1]}
    <HostDetail ip={decodeURIComponent(parts[1])} {reloadKey} />
  {:else if section === 'hosts'}
    <Hosts {reloadKey} />
  {:else if section === 'flows'}
    <Flows {reloadKey} />
  {:else if section === 'threats'}
    <Threats {reloadKey} />
  {:else if section === 'enrichment'}
    <Enrichment {reloadKey} />
  {:else if section === 'nicknames'}
    <Nicknames {reloadKey} />
  {:else if section === 'alerts'}
    <Alerts {reloadKey} />
  {:else if section === 'rules'}
    <Rules {reloadKey} />
  {:else if section === 'ids'}
    <IDS {reloadKey} />
  {:else if section === 'security'}
    <Security {reloadKey} />
  {:else}
    <div class="empty">Not found</div>
  {/if}
</main>

<footer class="muted small">
  {#if meta}
    data {fmtTime(meta.data_from)} → {fmtTime(meta.data_to)} · local networks: <span class="mono">{meta.local_networks.join(', ')}</span>
  {/if}
</footer>

{#if showChangePw}
  <div class="modal" role="dialog" onclick={(e) => { if (e.target === e.currentTarget) showChangePw = false }} onkeydown={(e) => { if (e.key === 'Escape') showChangePw = false }} tabindex="-1">
    <div class="modal-body">
      <ChangePassword forced={false} />
      <button class="small" style="margin-top:.5rem" onclick={() => (showChangePw = false)}>Close</button>
    </div>
  </div>
{/if}
{/if}

<style>
  header { display: flex; align-items: center; gap: 1.25rem; padding: .6rem 1.25rem; background: var(--surface-1); border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 5; flex-wrap: wrap; }
  .brand { font-weight: 600; font-size: 1.05rem; }
  .logo { color: var(--accent); }
  nav { display: flex; gap: .25rem; }
  nav a { padding: .35rem .7rem; border-radius: 6px; color: var(--text-secondary); }
  nav a:hover { background: var(--surface-2); text-decoration: none; }
  nav a.active { background: var(--surface-3); color: var(--text-primary); }
  .navbadge { display: inline-block; margin-left: .35rem; padding: 0 .35rem; border-radius: 999px; font-size: .7rem; background: var(--warning); color: #000; font-weight: 600; }
  .navbadge.crit { background: var(--critical); color: #fff; }
  .usermenu { position: relative; }
  .userbtn { background: var(--surface-2); }
  .menu { position: absolute; right: 0; top: calc(100% + .3rem); background: var(--surface-2); border: 1px solid var(--border); border-radius: 6px; display: flex; flex-direction: column; min-width: 160px; z-index: 10; box-shadow: 0 6px 20px rgba(0,0,0,.4); }
  .menu button { border: 0; background: transparent; text-align: left; padding: .5rem .75rem; border-radius: 0; }
  .menu button:hover { background: var(--surface-3); }
  .boot { min-height: 100vh; display: grid; place-items: center; color: var(--text-muted); }
  .modal { position: fixed; inset: 0; background: rgba(0,0,0,.5); display: grid; place-items: center; z-index: 20; }
  .modal-body { width: 380px; max-width: 95%; }
  main { padding: 1.25rem; max-width: 2200px; margin: 0 auto; }
  footer { padding: 1rem 1.25rem; border-top: 1px solid var(--border); }
</style>
