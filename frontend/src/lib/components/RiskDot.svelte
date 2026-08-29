<script lang="ts">
  import type { HostRisk } from '../api'
  let { risk }: { risk?: HostRisk | null } = $props()
  let level = $derived(!risk ? '' : risk.critical > 0 ? 'critical' : risk.warning > 0 ? 'warning' : 'info')
  let title = $derived(!risk ? '' : `risk ${risk.score}: ${risk.critical} critical, ${risk.warning} warning, ${risk.info} info`)
</script>
{#if risk}<span class="dot {level}" {title}>●</span>{/if}
<style>
  .dot { font-size: .7rem; vertical-align: middle; }
  .dot.critical { color: var(--critical); }
  .dot.warning { color: var(--warning); }
  .dot.info { color: var(--text-muted); }
</style>
