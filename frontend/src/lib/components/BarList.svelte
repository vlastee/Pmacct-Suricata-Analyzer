<script lang="ts">
  import { fmtBytes, pct } from '../format'
  import type { Snippet } from 'svelte'
  interface Item { label: string; value: number; href?: string; sub?: string }
  let { items, title, color = 'var(--series-1)', extra }: { items: Item[]; title: string; color?: string; extra?: Snippet<[Item]> } = $props()
  let max = $derived(Math.max(1, ...items.map(i => i.value)))
  let total = $derived(items.reduce((a, b) => a + b.value, 0))
</script>

<div class="card">
  <h3>{title}</h3>
  {#if !items.length}
    <div class="empty">No data</div>
  {:else}
    <ul>
      {#each items as it}
        <li>
          <div class="line">
            <span class="label">
              {#if it.href}<a href={it.href}>{it.label}</a>{:else}{it.label}{/if}
              {#if it.sub}<span class="muted small"> {it.sub}</span>{/if}
              {#if extra}{@render extra(it)}{/if}
            </span>
            <span class="val mono">{fmtBytes(it.value)} <span class="muted">{pct(it.value, total)}</span></span>
          </div>
          <div class="bar"><div style="width:{(100 * it.value) / max}%; background:{color}"></div></div>
        </li>
      {/each}
    </ul>
  {/if}
</div>

<style>
  ul { list-style: none; margin: 0; padding: 0; }
  li { margin-bottom: .5rem; }
  .line { display: flex; justify-content: space-between; gap: .5rem; font-size: .88rem; }
  .label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .val { white-space: nowrap; }
  .bar { height: 6px; background: var(--surface-3); border-radius: 3px; margin-top: 3px; overflow: hidden; }
  .bar div { height: 100%; border-radius: 3px; }
</style>
