<script lang="ts">
  let { error = null, loading = false }: { error?: string | null; loading?: boolean } = $props()
</script>
{#if error}
  <div class="card error">Error: {error}</div>
{:else if loading}
  <div class="empty">Loading…</div>
{/if}
