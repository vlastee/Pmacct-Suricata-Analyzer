<script lang="ts">
  import { api } from '../lib/api'
  import { auth } from '../lib/auth.svelte'

  let { forced = false }: { forced?: boolean } = $props()
  let current = $state('')
  let next = $state('')
  let confirm = $state('')
  let error = $state<string | null>(null)
  let ok = $state(false)
  let busy = $state(false)

  async function submit(e: Event) {
    e.preventDefault()
    error = null; ok = false
    if (next !== confirm) { error = 'New passwords do not match'; return }
    busy = true
    try {
      await api.changePassword(current, next)
      ok = true
      current = next = confirm = ''
      await auth.refresh()   // clears mustChange, reveals the app
    } catch (err: any) {
      error = err.message || 'Change failed'
    } finally {
      busy = false
    }
  }
</script>

<div class="wrap" class:full={forced}>
  <form class="card box" onsubmit={submit}>
    {#if forced}
      <div class="brand"><span class="logo">▲</span> Pmacct Analyzer</div>
      <h2>Set a new password</h2>
      <p class="secondary small">You are using the default password. Choose a new one to continue.</p>
    {:else}
      <h3>Change password</h3>
    {/if}
    <label>Current password<input type="password" bind:value={current} autocomplete="current-password" required /></label>
    <label>New password<input type="password" bind:value={next} autocomplete="new-password" minlength="8" required /></label>
    <label>Confirm new password<input type="password" bind:value={confirm} autocomplete="new-password" required /></label>
    <div class="muted small">At least 8 characters.</div>
    {#if error}<div class="error small">{error}</div>{/if}
    {#if ok}<div class="small" style="color:var(--good)">Password changed.</div>{/if}
    <button class="primary" type="submit" disabled={busy}>{busy ? 'Saving…' : 'Change password'}</button>
  </form>
</div>

<style>
  .wrap.full { min-height: 100vh; display: grid; place-items: center; padding: 1rem; }
  .box { width: 360px; max-width: 100%; display: flex; flex-direction: column; gap: .7rem; padding: 1.5rem; }
  .brand { font-weight: 600; font-size: 1.1rem; }
  .logo { color: var(--accent); }
  h2, h3 { margin: 0; }
  label { display: flex; flex-direction: column; gap: .25rem; font-size: .85rem; color: var(--text-secondary); }
</style>
