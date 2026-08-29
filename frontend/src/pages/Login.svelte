<script lang="ts">
  import { auth } from '../lib/auth.svelte'
  import { ApiError } from '../lib/api'

  let username = $state('admin')
  let password = $state('')
  let error = $state<string | null>(null)
  let retry = $state<number | null>(null)
  let busy = $state(false)

  async function submit(e: Event) {
    e.preventDefault()
    error = null; retry = null; busy = true
    try {
      await auth.login(username.trim(), password)
    } catch (err: any) {
      if (err instanceof ApiError && err.status === 429) {
        error = 'Too many failed attempts — this address is temporarily locked out.'
      } else {
        error = err.message || 'Login failed'
      }
    } finally {
      busy = false
    }
  }
</script>

<div class="wrap">
  <form class="card login" onsubmit={submit}>
    <div class="brand"><span class="logo">▲</span> Pmacct Analyzer</div>
    <h2>Sign in</h2>
    <label>Username<input bind:value={username} autocomplete="username" required /></label>
    <label>Password<input type="password" bind:value={password} autocomplete="current-password" required /></label>
    {#if error}<div class="error small">{error}{#if retry} Try again in {retry}s.{/if}</div>{/if}
    <button class="primary" type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
  </form>
</div>

<style>
  .wrap { min-height: 100vh; display: grid; place-items: center; padding: 1rem; }
  .login { width: 340px; max-width: 100%; display: flex; flex-direction: column; gap: .8rem; padding: 1.5rem; }
  .brand { font-weight: 600; font-size: 1.1rem; }
  .logo { color: var(--accent); }
  h2 { margin: 0; }
  label { display: flex; flex-direction: column; gap: .25rem; font-size: .85rem; color: var(--text-secondary); }
  input { font-size: 1rem; }
  button { margin-top: .3rem; }
</style>
