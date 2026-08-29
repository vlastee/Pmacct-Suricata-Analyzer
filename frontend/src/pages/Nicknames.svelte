<script lang="ts">
  import { api, type Nickname } from '../lib/api'
  import { fmtTime } from '../lib/format'
  import { router } from '../lib/router.svelte'
  import Loading from '../lib/components/Loading.svelte'
  import Th from '../lib/components/Th.svelte'
  import { Sorter } from '../lib/sort.svelte'
  const sorter = new Sorter('nickname', 'asc')

  let { reloadKey }: { reloadKey: number } = $props()
  let items = $state<Nickname[]>([])
  let error = $state<string | null>(null)
  let search = $state('')
  let ip = $state(''), nickname = $state(''), note = $state(''), kind = $state('other')
  const kinds = ['pc', 'phone', 'server', 'iot', 'network', 'other']
  let msg = $state('')
  let editingIP = $state<string | null>(null)

  let sorted = $derived(sorter.apply(items))
  async function load() {
    error = null
    try { items = (await api.nicknames(search)).items } catch (e: any) { error = e.message }
  }
  $effect(() => { void reloadKey; load() })

  async function save(e: Event) {
    e.preventDefault(); msg = ''
    try {
      await api.setNickname(ip.trim(), nickname.trim(), note.trim() || null, kind)
      ip = ''; nickname = ''; note = ''; kind = 'other'; editingIP = null
      await load()
    } catch (err: any) { msg = err.message }
  }
  function edit(n: Nickname) { editingIP = n.ip; ip = n.ip; nickname = n.nickname; note = n.note ?? ''; kind = n.kind || 'other'; window.scrollTo({ top: 0, behavior: 'smooth' }) }
  async function remove(n: Nickname) {
    if (!confirm(`Remove nickname "${n.nickname}" from ${n.ip}?`)) return
    try { await api.deleteNickname(n.ip); await load() } catch (err: any) { msg = err.message }
  }
</script>

<p class="muted small">Nicknames label local and external addresses everywhere in the UI (hosts, peers, flows, threats) and are searchable on the Hosts page.</p>

<form class="card row" style="margin-bottom:1rem" onsubmit={save}>
  <strong>{editingIP ? 'Edit' : 'Add'}</strong>
  <input placeholder="IP address" bind:value={ip} size="24" required disabled={!!editingIP} />
  <input placeholder="Nickname" bind:value={nickname} size="20" maxlength="100" required />
  <select bind:value={kind}>{#each kinds as k}<option>{k}</option>{/each}</select>
  <input placeholder="Note (optional)" bind:value={note} size="40" />
  <button type="submit" class="primary">Save</button>
  {#if editingIP}<button type="button" onclick={() => { editingIP = null; ip = ''; nickname = ''; note = '' }}>Cancel</button>{/if}
  {#if msg}<span class="error small">{msg}</span>{/if}
</form>

<Loading {error} />
<div class="card overflow">
  <form class="row" style="margin-bottom:.75rem" onsubmit={(e) => { e.preventDefault(); load() }}>
    <h3 style="margin:0">Nicknames ({items.length})</h3>
    <span class="spacer"></span>
    <input placeholder="Search" bind:value={search} size="24" />
    <button type="submit">Search</button>
  </form>
  <table>
    <thead><tr>
      <Th sorter={sorter} key="nickname" label="Nickname" />
      <Th sorter={sorter} key="ip" label="IP" />
      <Th sorter={sorter} key="kind" label="Kind" />
      <Th sorter={sorter} key="note" label="Note" />
      <Th sorter={sorter} key="updated_at" label="Updated" num />
      <th></th>
    </tr></thead>
    <tbody>
      {#each sorted as n (n.ip)}
        <tr>
          <td><strong>{n.nickname}</strong></td>
          <td><a class="mono" href={router.href(`/hosts/${n.ip}`)}>{n.ip}</a></td>
          <td><span class="badge">{n.kind}</span></td>
          <td class="secondary small">{n.note ?? ''}</td>
          <td class="num small">{fmtTime(n.updated_at)}</td>
          <td class="num"><button class="small" onclick={() => edit(n)}>Edit</button> <button class="small" onclick={() => remove(n)}>Delete</button></td>
        </tr>
      {:else}<tr><td colspan="6" class="empty">No nicknames yet — add one above or from any host page.</td></tr>{/each}
    </tbody>
  </table>
</div>
