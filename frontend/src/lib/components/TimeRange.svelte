<script lang="ts">
  import { router, RANGES, currentRange } from '../router.svelte'
  let range = $derived(currentRange())
  let auto = $state(true)
  let timer: ReturnType<typeof setInterval> | undefined
  let { onrefresh }: { onrefresh?: () => void } = $props()
  $effect(() => {
    clearInterval(timer)
    if (auto) timer = setInterval(() => onrefresh?.(), 60_000)
    return () => clearInterval(timer)
  })
</script>

<div class="row">
  <div class="seg" role="group" aria-label="Time range">
    {#each RANGES as r}
      <button class:active={range.since === r.since && !range.until} onclick={() => router.setQuery({ since: r.since, until: undefined })}>{r.label}</button>
    {/each}
  </div>
  <label class="small muted"><input type="checkbox" bind:checked={auto} /> auto-refresh</label>
  <button onclick={() => onrefresh?.()} title="Refresh now">↻</button>
</div>
