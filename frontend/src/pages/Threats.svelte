<script lang="ts">
  import { api, type Threat } from '../lib/api'
  import { currentRange, router } from '../lib/router.svelte'
  import { fmtBytes, fmtCompact, fmtTime } from '../lib/format'
  import IPLabel from '../lib/components/IPLabel.svelte'
  import Loading from '../lib/components/Loading.svelte'
  import Th from '../lib/components/Th.svelte'
  import { Sorter } from '../lib/sort.svelte'
  const sorter = new Sorter('malicious')

  let { reloadKey }: { reloadKey: number } = $props()
  let items = $state<Threat[]>([])
  let error = $state<string | null>(null)
  let loading = $state(false)
  let sorted = $derived(sorter.apply(items, (t, k) => k === 'ip' ? (t.nickname ?? t.ip) : k === 'tags' ? t.tags.join(', ') : k === 'local_hosts' ? t.local_hosts.join(', ') : (t as any)[k]))
  async function load() {
    loading = true; error = null
    try { items = (await api.threats(currentRange())).items } catch (e: any) { error = e.message } finally { loading = false }
  }
  $effect(() => { void reloadKey; void router.route.query.toString(); load() })
</script>

<p class="muted small">External IPs that appeared in traffic during the selected window and that VirusTotal engines flagged as malicious or suspicious.</p>
<Loading {error} loading={loading && !items.length} />
<div class="card overflow">
  <table>
    <thead><tr>
      <Th sorter={sorter} key="ip" label="IP" />
      <Th sorter={sorter} key="malicious" label="Malicious" num />
      <Th sorter={sorter} key="suspicious" label="Suspicious" num />
      <Th sorter={sorter} key="tags" label="Tags" />
      <Th sorter={sorter} key="local_hosts" label="Local hosts involved" />
      <Th sorter={sorter} key="bytes" label="Bytes" num />
      <Th sorter={sorter} key="flows" label="Flows" num />
      <Th sorter={sorter} key="last_seen" label="Last seen" num />
    </tr></thead>
    <tbody>
      {#each sorted as t (t.ip)}
        <tr>
          <td><IPLabel ip={t.ip} nickname={t.nickname} info={t.info} /></td>
          <td class="num"><span class="badge critical">{t.malicious}</span></td>
          <td class="num"><span class="badge warning">{t.suspicious}</span></td>
          <td class="small">{t.tags.join(', ') || '–'}</td>
          <td>{#each t.local_hosts as h, i}{#if i}, {/if}<a class="mono" href={router.href(`/hosts/${h}`)}>{h}</a>{/each}</td>
          <td class="num">{fmtBytes(t.bytes)}</td><td class="num">{fmtCompact(t.flows)}</td><td class="num">{fmtTime(t.last_seen)}</td>
        </tr>
      {:else}<tr><td colspan="8" class="empty">Nothing flagged in this window 🎉</td></tr>{/each}
    </tbody>
  </table>
</div>
