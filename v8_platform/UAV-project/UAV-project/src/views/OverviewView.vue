<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink } from 'vue-router'
import { useSimulationStore } from '@/stores/simulation'
import { SCENARIOS } from '@/config/scenarios'
import PageHeader from '@/components/common/PageHeader.vue'
import RunControls from '@/components/common/RunControls.vue'
import MetricCard from '@/components/common/MetricCard.vue'
import EventTable from '@/components/common/EventTable.vue'
import ScenarioTopology from '@/components/topology/ScenarioTopology.vue'
import TimeSeriesChart from '@/components/charts/TimeSeriesChart.vue'
import ScenarioGlyph from '@/components/common/ScenarioGlyph.vue'
import ReportScopeSummary from '@/components/common/ReportScopeSummary.vue'
import { humanizeAttackSubtype } from '@/utils/runtimeFormat'

const store = useSimulationStore()
const hasRun = computed(() => Boolean(store.runMetadata))
const detectionLabel = computed(() => !hasRun.value ? '检测规则：等待运行' : store.runMetadata?.run_config?.flooding_detection_enabled === false ? '专项演示：基础安全校验' : store.activeRunFamily === 'DOS' ? '专项检测：报文洪泛' : '综合检测：洪泛已启用')
const attackPlan = computed(() => store.runMetadata?.attack_plan?.[0] ?? null)
const legitimateNodes = computed(() => store.runMetadata?.legitimate_node_count ?? store.topology?.nodes.filter((node) => node.role !== 'EXTERNAL').length ?? '—')
const attackCount = computed(() => store.runMetadata ? store.runMetadata.attack_plan?.length ?? 0 : '—')
const reportCount = computed(() => store.runMetadata ? store.securityReports.length : '—')
const defenseCount = computed(() => store.runMetadata ? store.executedDefenseCount : '—')
const chartLabels = computed(() => store.history.map((point) => `${point.simTimeS.toFixed(1)}s`))
const chartSeries = computed(() => [
  { name: 'GCS接收平均吞吐量', color: '#246fe5', area: true, yAxisIndex: 0 as const, data: store.history.map((point) => point.throughputMbps) },
  { name: '安全报告累计', color: '#d94857', yAxisIndex: 1 as const, data: store.history.map((point) => point.securityReportCount) },
])
const entries = Object.values(SCENARIOS).filter((scenario) => scenario.family)
</script>

<template>
  <div class="page-grid overview-page">
    <PageHeader eyebrow="Overview / Runtime" title="系统总览" description="统一查看当前编队、五类攻击场景、安全报告与运行指标。" :detection-label="detectionLabel" :protection-label="hasRun ? '处置：以执行证据为准' : '处置：等待运行'" />
    <section class="panel run-toolbar"><RunControls scenario="overview" launch-label="创建基础运行" /></section>

    <section class="grid-4">
      <MetricCard label="合法节点数（当前配置）" :value="legitimateNodes" :note="hasRun ? '' : '尚未创建仿真运行'" :tone="hasRun ? 'blue' : 'slate'" icon="N" />
      <MetricCard label="当前运行攻击计划数" :value="attackCount" :note="attackPlan ? `${attackPlan.attack_family} · ${humanizeAttackSubtype(attackPlan.attack_subtype)}` : hasRun ? '当前运行无攻击计划' : '尚未创建仿真运行'" :tone="attackPlan ? 'red' : 'slate'" icon="!" />
      <MetricCard label="GCS 安全报告数" :value="reportCount" :note="hasRun ? '' : '尚未创建仿真运行'" :tone="store.securityReports.length ? 'orange' : 'slate'" icon="A" />
      <MetricCard label="GCS 可见已执行处置" :value="defenseCount" :note="hasRun ? '' : '尚未创建仿真运行'" :tone="store.executedDefenseCount ? 'green' : 'slate'" icon="✓" />
    </section>

    <section class="overview-middle">
      <article class="panel topology-panel">
        <div class="panel-header"><div><span class="source-label source-truth">场景配置 / 仿真真值</span><h2 class="panel-title">场景拓扑</h2></div></div>
        <ScenarioTopology mode="overview" :topology="store.topology" :attack-plan="attackPlan" :reports="store.securityReports" :run-state="store.status?.state" :encrypted="store.runMetadata?.run_config?.encrypt_sensitive === true" />
      </article>
      <article class="panel scenario-panel">
        <div class="panel-header"><div><h2 class="panel-title">五个正式攻击场景</h2></div></div>
        <div class="scenario-list">
          <RouterLink v-for="scenario in entries" :key="scenario.key" :to="scenario.route" class="scenario-entry">
            <div class="scenario-mark" :class="scenario.key"><ScenarioGlyph :scenario="scenario.key" /></div>
            <div><strong>{{ scenario.shortTitle }}</strong><span>{{ scenario.mechanism }}</span></div><b>›</b>
          </RouterLink>
        </div>
      </article>
    </section>

    <section class="grid-2">
      <article class="panel">
        <div class="panel-header"><div><span class="source-label source-online">在线 Runtime</span><h2 class="panel-title">最近安全事件</h2></div></div>
        <ReportScopeSummary :reports="store.securityReports" :cross-category="Boolean(attackPlan && attackPlan.attack_family !== 'DOS')" />
        <EventTable :reports="store.securityReports" :limit="7" :node-roles="store.runMetadata?.node_roles" />
      </article>
      <article class="panel">
        <div class="panel-header"><div><span class="source-label source-online">在线数据</span><h2 class="panel-title">运行趋势</h2></div></div>
        <TimeSeriesChart :labels="chartLabels" :series="chartSeries" unit="Mbps" secondary-unit="条" />
      </article>
    </section>
  </div>
</template>

<style scoped>
.run-toolbar { padding: 14px 16px; }.overview-middle { display: grid; grid-template-columns: minmax(0,1.55fr) minmax(320px,.7fr); gap: 18px; }.topology-panel { min-height: 520px; }.scenario-list { display: grid; gap: 9px; }.scenario-entry { display: grid; grid-template-columns: 42px minmax(0,1fr) auto; align-items: center; gap: 12px; padding: 13px 12px; border: 1px solid #e1e7ef; border-radius: 10px; transition: .18s ease; }.scenario-entry:hover { border-color: #9ac0f3; transform: translateY(-1px); box-shadow: 0 6px 16px rgba(35,92,162,.08); }.scenario-entry strong,.scenario-entry span { display: block; }.scenario-entry strong { font-size: 12px; }.scenario-entry span { margin-top: 4px; overflow: hidden; color: #7b899b; font-size: 11px; text-overflow: ellipsis; white-space: nowrap; }.scenario-entry > b { color: #9ba8b8; font-size: 22px; }.scenario-mark { display: grid; place-items: center; width: 42px; height: 42px; border-radius: 10px; color: #2d6dbd; background: #e8f2ff; }.scenario-mark.spoofing,.scenario-mark.fdi { color: #c73d4c; background: #fee9ec; }.scenario-mark.dos { color: #b36c13; background: #fff0d4; }.scenario-mark.eavesdropping { color: #6550b7; background: #eeeaff; }.scenario-mark.replay { color: #16825a; background: #dcf7e9; }
@media (max-width: 1120px) { .overview-middle { grid-template-columns: 1fr; } }
</style>
