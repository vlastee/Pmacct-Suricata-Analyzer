<script lang="ts">
  let { label, value, sub = '' }: { label: string; value: string; sub?: string } = $props()
</script>

<div class="tile card">
  <div class="label">{label}</div>
  <div class="value">{value}</div>
  {#if sub}<div class="sub">{sub}</div>{/if}
</div>

<style>
  .tile { padding: .8rem 1rem; }
  .label { color: var(--text-muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .05em; }
  .value { font-size: 1.5rem; font-weight: 600; font-variant-numeric: tabular-nums; margin-top: .15rem; }
  .sub { color: var(--text-secondary); font-size: .8rem; margin-top: .1rem; }
</style>
