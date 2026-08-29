<script lang="ts">
  let { sev, count = 0 }: { sev: string; count?: number } = $props()
  const cls: Record<string, string> = { critical: 'critical', warning: 'warning', info: '' }
  const icon: Record<string, string> = { critical: '⛔', warning: '⚠', info: 'ℹ' }
</script>
<span class="badge {cls[sev] ?? ''}" title={sev}>{icon[sev] ?? ''} {sev}{#if count > 1} ×{count}{/if}</span>
