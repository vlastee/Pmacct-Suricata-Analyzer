<script lang="ts">
  import type { IPInfo, HostRisk } from '../api'
  import { flag } from '../format'
  import { router } from '../router.svelte'
  import RiskDot from './RiskDot.svelte'
  import { exclusions } from '../exclusions.svelte'
  let { ip, local = false, info = null, link = true, nickname = null, names = [], risk = null }:
    { ip: string; local?: boolean; info?: IPInfo | null; link?: boolean; nickname?: string | null; names?: string[]; risk?: HostRisk | null } = $props()
  let primaryName = $derived(names && names.length ? names[0] : null)
  let vtBad = $derived(info?.vt && ((info.vt.malicious ?? 0) > 0 || (info.vt.suspicious ?? 0) > 0))
  let trusted = $derived(exclusions.match(ip, info?.hostname ? [info.hostname, ...names] : names))
</script>

<span class="ipl">
  <RiskDot {risk} />
  {#if nickname}<a class="nick" href={link ? router.href(`/hosts/${ip}`) : undefined}>{nickname}</a>{/if}
  {#if link}<a class="mono" class:dim={!!nickname} href={router.href(`/hosts/${ip}`)}>{ip}</a>{:else}<span class="mono">{ip}</span>{/if}
  {#if primaryName && !nickname}<span class="dns small muted" title={names.join('\n')}>{primaryName}{#if names.length > 1} +{names.length - 1}{/if}</span>{/if}
  {#if local}<span class="badge local">local</span>{/if}
  {#if trusted}<span class="badge good" title="excluded from alerts by pattern {trusted.pattern}">trusted</span>{/if}
  {#if vtBad}<span class="badge critical" title="VirusTotal: {info?.vt?.malicious} malicious, {info?.vt?.suspicious} suspicious">⚠ {info?.vt?.malicious}/{info?.vt?.suspicious}</span>{/if}
  {#if info}
    <span class="meta small muted">
      {#if info.country_code}<span class="flag" title={info.country ?? ''}>{flag(info.country_code)}</span>{/if}
      {info.hostname ?? info.org ?? info.as_org ?? info.isp ?? ''}
      {#if info.is_hosting}<span class="badge">hosting</span>{/if}
      {#if info.is_proxy}<span class="badge warning">proxy</span>{/if}
    </span>
  {/if}
</span>

<style>
  .ipl { display: inline-flex; gap: .4rem; align-items: baseline; max-width: 100%; }
  .nick { font-weight: 600; color: var(--text-primary); }
  .dim { color: var(--text-muted); font-size: .85em; }
  .meta { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 420px; }
</style>
