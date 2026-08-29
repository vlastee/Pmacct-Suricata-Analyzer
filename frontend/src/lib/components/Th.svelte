<script lang="ts">
  import type { Sorter } from '../sort.svelte'
  let { sorter, key, label, num = false }: { sorter: Sorter; key: string; label: string; num?: boolean } = $props()
  let active = $derived(sorter.key === key)
</script>

<th class="sortable" class:num class:active onclick={() => sorter.toggle(key, num)} title="Sort by {label}">
  {label}{#if active}<span class="arrow">{sorter.dir === 'desc' ? '▾' : '▴'}</span>{/if}
</th>

<style>
  th.active { color: var(--text-primary); }
  .arrow { margin-left: .2rem; }
</style>
