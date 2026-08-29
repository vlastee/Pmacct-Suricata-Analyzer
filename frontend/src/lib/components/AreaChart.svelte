<script lang="ts">
  import type { Bucket } from '../api'
  import { fmtBytes, fmtRate, fmtTime } from '../format'

  let { points, interval, height = 220, title = 'Traffic' }: { points: Bucket[]; interval: number; height?: number; title?: string } = $props()

  const pad = { top: 12, right: 12, bottom: 26, left: 56 }
  let width = $state(800)
  let hover = $state<number | null>(null)

  // Two series, fixed slots: in = series-1 (blue), out = series-2 (orange).
  let series = $derived([
    { key: 'bytes_in', label: 'Inbound', color: 'var(--series-1)' },
    { key: 'bytes_out', label: 'Outbound', color: 'var(--series-2)' },
  ] as const)

  let maxY = $derived(Math.max(1, ...points.map(p => Math.max(p.bytes_in, p.bytes_out))))
  let x = $derived((i: number) => pad.left + (points.length <= 1 ? 0 : (i / (points.length - 1)) * (width - pad.left - pad.right)))
  let y = $derived((v: number) => pad.top + (1 - v / maxY) * (height - pad.top - pad.bottom))

  function path(key: 'bytes_in' | 'bytes_out', area: boolean): string {
    if (!points.length) return ''
    const pts = points.map((p, i) => `${x(i).toFixed(1)},${y(p[key]).toFixed(1)}`)
    const line = `M${pts.join('L')}`
    if (!area) return line
    return `${line}L${x(points.length - 1).toFixed(1)},${y(0).toFixed(1)}L${x(0).toFixed(1)},${y(0).toFixed(1)}Z`
  }

  let ticksY = $derived([0, 0.25, 0.5, 0.75, 1].map(f => f * maxY))
  let ticksX = $derived(() => {
    const n = Math.min(6, points.length)
    if (n < 2) return points.map((_, i) => i)
    const out: number[] = []
    for (let k = 0; k < n; k++) out.push(Math.round((k * (points.length - 1)) / (n - 1)))
    return out
  })

  function onmove(e: MouseEvent) {
    if (!points.length) return
    const rect = (e.currentTarget as SVGElement).getBoundingClientRect()
    const px = ((e.clientX - rect.left) / rect.width) * width
    const rel = (px - pad.left) / (width - pad.left - pad.right)
    hover = Math.max(0, Math.min(points.length - 1, Math.round(rel * (points.length - 1))))
  }
</script>

<div class="chart" bind:clientWidth={width}>
  <div class="row small" style="margin-bottom:.35rem">
    <span class="secondary">{title}</span>
    <span class="spacer"></span>
    {#each series as s}
      <span class="legend"><i style="background:{s.color}"></i>{s.label}</span>
    {/each}
  </div>
  {#if !points.length}
    <div class="empty">No traffic in this window</div>
  {:else}
    <svg viewBox="0 0 {width} {height}" {height} width="100%" onmousemove={onmove} onmouseleave={() => (hover = null)} role="img" aria-label={title}>
      {#each ticksY as t}
        <line x1={pad.left} x2={width - pad.right} y1={y(t)} y2={y(t)} class="grid" />
        <text x={pad.left - 6} y={y(t) + 4} class="tick" text-anchor="end">{fmtBytes(t, 0)}</text>
      {/each}
      {#each ticksX() as i}
        <text x={x(i)} y={height - 8} class="tick" text-anchor="middle">{fmtTime(points[i].time, interval >= 86400)}</text>
      {/each}
      {#each series as s}
        <path d={path(s.key, true)} fill={s.color} opacity="0.12" />
        <path d={path(s.key, false)} fill="none" stroke={s.color} stroke-width="2" stroke-linejoin="round" />
      {/each}
      {#if hover !== null}
        <line x1={x(hover)} x2={x(hover)} y1={pad.top} y2={height - pad.bottom} class="crosshair" />
        {#each series as s}
          <circle cx={x(hover)} cy={y(points[hover][s.key])} r="4" fill={s.color} stroke="var(--surface-1)" stroke-width="2" />
        {/each}
      {/if}
    </svg>
    {#if hover !== null}
      {@const p = points[hover]}
      <div class="tooltip" style="left:{Math.min(x(hover) / width * 100, 78)}%">
        <div class="secondary">{fmtTime(p.time)}</div>
        <div><i style="background:var(--series-1)"></i>In {fmtBytes(p.bytes_in)} <span class="muted">({fmtRate(p.bytes_in, interval)})</span></div>
        <div><i style="background:var(--series-2)"></i>Out {fmtBytes(p.bytes_out)} <span class="muted">({fmtRate(p.bytes_out, interval)})</span></div>
        <div class="muted">{p.flows} flows · {p.packets} pkts · total {fmtBytes(p.bytes)}</div>
      </div>
    {/if}
  {/if}
</div>

<style>
  .chart { position: relative; width: 100%; }
  svg { display: block; overflow: visible; }
  .grid { stroke: var(--border); stroke-width: 1; }
  .tick { fill: var(--text-muted); font-size: 11px; }
  .crosshair { stroke: var(--text-muted); stroke-dasharray: 3 3; }
  .legend i, .tooltip i { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: .35rem; vertical-align: -1px; }
  .legend { margin-left: .75rem; color: var(--text-secondary); }
  .tooltip { position: absolute; top: 28px; background: var(--surface-3); border: 1px solid var(--border); border-radius: 6px;
    padding: .4rem .6rem; font-size: .8rem; pointer-events: none; white-space: nowrap; box-shadow: 0 4px 16px rgba(0,0,0,.4); }
</style>
