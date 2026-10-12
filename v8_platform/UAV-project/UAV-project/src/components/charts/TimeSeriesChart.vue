<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts'

export interface ChartSeries {
  name: string
  data: Array<number | null>
  color: string
  dashed?: boolean
  area?: boolean
  step?: 'start' | 'middle' | 'end'
  yAxisIndex?: 0 | 1
}

const props = withDefaults(defineProps<{
  labels: string[]
  series: ChartSeries[]
  unit?: string
  secondaryUnit?: string
  height?: number
}>(), { unit: '', secondaryUnit: '', height: 260 })

const root = ref<HTMLDivElement | null>(null)
let chart: echarts.ECharts | null = null
let resizeObserver: ResizeObserver | null = null
const hasData = computed(() => props.labels.length > 0 && props.series.some((item) => item.data.some((value) => value !== null)))
const latestSeriesValues = computed(() => JSON.stringify(props.series.map((item) => ({
  name: item.name,
  value: [...item.data].reverse().find((value) => value !== null) ?? null,
}))))

function ensureChart() {
  if (!root.value) return null
  chart = echarts.getInstanceByDom(root.value) ?? echarts.init(root.value)
  return chart
}

function render() {
  const instance = ensureChart()
  if (!instance) return
  if (!hasData.value) {
    instance.clear()
    return
  }
  const hasSecondaryAxis = props.series.some((item) => item.yAxisIndex === 1)
  const axis = (name: string, position: 'left' | 'right') => ({
    type: 'value',
    name,
    position,
    nameTextStyle: { color: '#8794a6', fontSize: 11 },
    axisLabel: { color: '#8794a6', fontSize: 11 },
    splitLine: position === 'left' ? { lineStyle: { color: '#edf1f5', type: 'dashed' } } : { show: false },
  })
  instance.setOption({
    animationDuration: 280,
    color: props.series.map((item) => item.color),
    tooltip: { trigger: 'axis', backgroundColor: '#16273c', borderWidth: 0, textStyle: { color: '#fff', fontSize: 11 } },
    legend: { show: false },
    grid: { left: 50, right: hasSecondaryAxis ? 50 : 18, top: 38, bottom: 30 },
    xAxis: { type: 'category', boundaryGap: false, data: props.labels, axisLine: { lineStyle: { color: '#d8e0e9' } }, axisLabel: { color: '#8794a6', fontSize: 11 } },
    yAxis: hasSecondaryAxis
      ? [axis(props.unit, 'left'), axis(props.secondaryUnit, 'right')]
      : axis(props.unit, 'left'),
    series: props.series.map((item) => ({
      name: item.name, type: 'line', smooth: !item.step, step: item.step, yAxisIndex: item.yAxisIndex ?? 0,
      connectNulls: false, showSymbol: props.labels.length <= 1, symbolSize: 6, data: item.data,
      lineStyle: { width: 2, type: item.dashed ? 'dashed' : 'solid' },
      areaStyle: item.area ? { opacity: .08 } : undefined,
    })),
  }, true)
}

function resize() { chart?.resize() }
onMounted(() => {
  void nextTick(() => {
    ensureChart()
    render()
    if (root.value && typeof ResizeObserver !== 'undefined') {
      resizeObserver = new ResizeObserver(resize)
      resizeObserver.observe(root.value)
    }
  })
  window.addEventListener('resize', resize)
})
watch(() => [props.labels, props.series, props.unit, props.secondaryUnit], () => void nextTick(render), { deep: true })
onBeforeUnmount(() => {
  window.removeEventListener('resize', resize)
  resizeObserver?.disconnect()
  resizeObserver = null
  chart?.dispose()
  chart = null
})
</script>

<template>
  <div
    class="time-chart-shell"
    :style="{ height: `${height}px` }"
    :data-has-data="hasData"
    :data-point-count="labels.length"
    :data-series-latest="latestSeriesValues"
    :aria-label="`趋势图，共 ${labels.length} 个数据点`"
  >
    <div class="chart-legend" aria-label="图例"><span v-for="item in series" :key="item.name"><i :style="{ background: item.color }"></i>{{ item.name }}</span></div>
    <div ref="root" class="time-chart"></div>
    <div v-show="!hasData" class="empty-state chart-empty"><div><strong>暂无趋势数据</strong>场景运行后显示在线采样趋势。</div></div>
  </div>
</template>

<style scoped>
.time-chart-shell { position: relative; width: 100%; min-height: 180px; }
.chart-legend { display:flex;flex-wrap:wrap;gap:8px 16px;min-height:32px;padding:0 8px 8px;color:#64748b;font-size:12px; }
.chart-legend span { display:flex;align-items:center;gap:7px; }.chart-legend i { width:18px;height:3px;display:inline-block; }
.time-chart { width: 100%; height: calc(100% - 40px); }
.chart-empty { position: absolute; inset: 0; z-index: 1; background: #fff; }
</style>
