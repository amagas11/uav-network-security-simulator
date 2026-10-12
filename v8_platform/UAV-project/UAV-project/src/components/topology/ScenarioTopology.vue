<script setup lang="ts">
import { computed } from 'vue'
import type { AttackSpec, CausalCapture, ScenarioTopology, SecurityReport, TopologyLink } from '@/api'
import {
  buildSemanticLayout,
  humanNodeName,
  materializeSceneNodes,
  type SemanticNode,
  type TopologyMode,
} from '@/config/topologyLayouts'
import {
  selectTargetDosReport,
  type PrimaryBusinessFlow,
} from '@/config/topologySemantics'
import TopologyNode from './TopologyNode.vue'
import { visibleQuadraticPath } from '@/utils/topologyGeometry'

const props = withDefaults(defineProps<{
  mode?: TopologyMode
  topology: ScenarioTopology | null
  attackPlan?: AttackSpec | null
  reports?: SecurityReport[]
  primaryFlow?: PrimaryBusinessFlow | null
  runState?: string | null
  showTruth?: boolean
  encrypted?: boolean
  capture?: CausalCapture | null
  receiverPeakRate?: number | null
}>(), {
  mode: 'overview',
  attackPlan: null,
  reports: () => [],
  primaryFlow: null,
  runState: null,
  showTruth: true,
  encrypted: false,
  capture: null,
  receiverPeakRate: null,
})

interface EdgeGeometry {
  path: string
  controlX: number
  controlY: number
  labelX: number
  labelY: number
}

const markerPrefix = computed(() => `topology-${props.mode}`)
const sourceNodes = computed(() => materializeSceneNodes(
  props.topology?.nodes ?? [],
  props.attackPlan,
  props.showTruth,
))
const layout = computed(() => buildSemanticLayout(
  props.mode,
  sourceNodes.value,
  props.topology?.links ?? [],
  props.attackPlan,
  props.primaryFlow,
))
const nodes = computed(() => layout.value.nodes)
const byId = computed(() => new Map(nodes.value.map((node) => [node.id, node])))
const primarySourceNode = computed(() => layout.value.primaryFlow === null
  ? null
  : byId.value.get(layout.value.primaryFlow.sourceId) ?? null)
const primaryTargetNode = computed(() => layout.value.primaryFlow === null
  ? null
  : byId.value.get(layout.value.primaryFlow.targetId) ?? null)
const targetNode = computed(() => layout.value.targetId === null ? null : byId.value.get(layout.value.targetId) ?? null)
const attackerNode = computed(() => layout.value.attackerId === null ? null : byId.value.get(layout.value.attackerId) ?? null)
const onPathFdi = computed(() => props.mode === 'fdi' && props.attackPlan?.parameters?.injection_mode === 'ON_PATH_INTERCEPTION_REPLACEMENT')
const copyFdi = computed(() => props.mode === 'fdi' && props.attackPlan?.parameters?.injection_mode === 'CAPTURE_MODIFY_INJECT')
const externalFdi = computed(() => onPathFdi.value || copyFdi.value)

const normalLinks = computed(() => {
  const seen = new Set<string>()
  return (props.topology?.links ?? []).filter((link) => {
    const src = byId.value.get(link.src)
    const dst = byId.value.get(link.dst)
    if (!src || !dst || src.role === 'EXTERNAL' || dst.role === 'EXTERNAL') return false
    if (
      props.mode !== 'overview'
      && edgeBetween(link, layout.value.primaryFlow?.sourceId ?? null, layout.value.primaryFlow?.targetId ?? null)
    ) return false
    const key = [link.src, link.dst].sort((a, b) => a - b).join(':')
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
})

function edgeBetween(link: TopologyLink, first: number | null, second: number | null): boolean {
  if (first === null || second === null) return false
  return (link.src === first && link.dst === second) || (link.src === second && link.dst === first)
}

function quadraticGeometry(a: SemanticNode, b: SemanticNode, bend = 0): EdgeGeometry {
  const dx = b.x - a.x
  const dy = b.y - a.y
  const length = Math.max(1, Math.hypot(dx, dy))
  const midpointX = (a.x + b.x) / 2
  const midpointY = (a.y + b.y) / 2
  const controlX = midpointX - dy / length * bend
  const controlY = midpointY + dx / length * bend
  const labelX = .25 * a.x + .5 * controlX + .25 * b.x
  const labelY = .25 * a.y + .5 * controlY + .25 * b.y
  return {
    path: visibleQuadraticPath(a, b, { x: controlX, y: controlY }, a.id === Number.MIN_SAFE_INTEGER ? 0 : 43, 43),
    controlX,
    controlY,
    labelX,
    labelY,
  }
}

function normalGeometry(link: TopologyLink, index: number): EdgeGeometry | null {
  const src = byId.value.get(link.src)
  const dst = byId.value.get(link.dst)
  if (!src || !dst) return null
  const bendByMode: Record<TopologyMode, number> = {
    overview: index % 2 ? 5 : -5,
    spoofing: index % 2 ? 8 : -8,
    fdi: index % 2 ? 7 : -7,
    dos: index % 2 ? 8 : -8,
    eavesdropping: index % 2 ? 7 : -7,
    replay: index % 2 ? 7 : -7,
  }
  return quadraticGeometry(src, dst, bendByMode[props.mode])
}

const primaryGeometry = computed(() => {
  if (!primarySourceNode.value || !primaryTargetNode.value) return null
  const bends: Record<TopologyMode, number> = {
    overview: 0, spoofing: -25, fdi: 0, dos: -26, eavesdropping: -14, replay: -18,
  }
  return quadraticGeometry(primarySourceNode.value, onPathFdi.value && attackerNode.value ? attackerNode.value : primaryTargetNode.value, bends[props.mode])
})
const attackGeometry = computed(() => {
  if (!props.showTruth || !props.attackPlan || !attackerNode.value || !targetNode.value || (props.mode === 'fdi' && !externalFdi.value) || props.mode === 'eavesdropping') return null
  const bends: Record<TopologyMode, number> = {
    overview: 22, spoofing: 30, fdi: 0, dos: 34, eavesdropping: 0, replay: 36,
  }
  return quadraticGeometry(attackerNode.value, targetNode.value, bends[props.mode])
})
const passiveGeometry = computed(() => {
  if (!(['spoofing', 'replay', 'eavesdropping'].includes(props.mode) || copyFdi.value) || !props.attackPlan || !props.showTruth || !attackerNode.value || !primaryGeometry.value || !primarySourceNode.value || !primaryTargetNode.value) return null
  const midpoint: SemanticNode = {
    ...primarySourceNode.value,
    id: Number.MIN_SAFE_INTEGER,
    x: primaryGeometry.value.labelX,
    y: primaryGeometry.value.labelY,
    emphasis: 'primary',
  }
  return quadraticGeometry(midpoint, attackerNode.value, props.mode === 'replay' ? 100 : -18)
})

const report = computed(() => {
  if (props.mode === 'dos') return selectTargetDosReport(props.reports, layout.value.targetId)
  const preferredCategory: Partial<Record<TopologyMode, string>> = {
    spoofing: 'AUTH_FAILURE', fdi: 'AUTH_FAILURE', dos: 'DOS', replay: 'REPLAY',
  }
  const category = preferredCategory[props.mode]
  const matching = category
    ? props.reports.filter((item) => String(item.category || '').toUpperCase() === category)
    : props.reports
  return matching[matching.length - 1] ?? null
})
const action = computed(() => report.value?.action_result?.executed
  ? report.value.action_result.request?.action ?? null
  : null)
const detected = computed(() => Boolean(report.value))
const evidenceReason = computed(() => String(
  report.value?.evidence?.reason
    ?? report.value?.evidence?.replay_check_result
    ?? report.value?.category
    ?? '',
))
const replayResult = computed(() => String(
  report.value?.evidence?.replay_check_result
    ?? report.value?.evidence?.reason
    ?? '',
))
const replaySequence = computed(() => report.value?.evidence?.sequence_no)
const replayHmac = computed(() => report.value?.evidence?.application_hmac_result)
const observedRate = computed(() => report.value?.evidence?.observed_packet_rate_pps ?? report.value?.evidence?.packet_rate_pps)
const thresholdRate = computed(() => report.value?.evidence?.flooding_threshold_pps ?? report.value?.evidence?.threshold_pps)
const detectorNodeLabel = computed(() => targetNode.value ? humanNodeName(targetNode.value) : '目标接收节点')
const configuredRate = computed(() => {
  const value = props.attackPlan?.intensity?.value
  return typeof value === 'number' && Number.isFinite(value) ? value : null
})
const isRunning = computed(() => props.runState === 'RUNNING')

const attackCopy = computed(() => {
  if (props.mode === 'spoofing') return { main: '身份伪装', technical: '仅修改声明身份' }
  if (props.mode === 'dos') return { main: configuredRate.value === null ? '应用层 Flooding' : `Flooding · ${configuredRate.value} pkt/s`, technical: 'FLOODING' }
  if (props.mode === 'replay') return { main: '已捕获合法报文原样重放', technical: replaySequence.value == null ? 'sequence —' : `sequence ${replaySequence.value}` }
  if (props.mode === 'eavesdropping') return { main: '被动截获', technical: '不发送数据' }
  if (props.mode === 'fdi') return { main: copyFdi.value ? '业务内容篡改' : onPathFdi.value ? '兼容中继替换' : '发送前业务内容篡改', technical: copyFdi.value ? '攻击副本注入 · 原 HMAC 不变' : '原 HMAC 标签不变' }
  const family = String(props.attackPlan?.attack_family || '')
  const human: Record<string, string> = { SPOOFING: '身份伪装', FDI: '业务内容篡改', DOS: '报文洪泛', EAVESDROPPING: '被动截获', REPLAY: '合法报文重放' }
  return { main: human[family] || '攻击关系', technical: props.attackPlan?.attack_subtype || family }
})

const floodPackets = computed(() => {
  const geometry = attackGeometry.value
  if (props.mode !== 'dos' || !geometry || !attackerNode.value || !targetNode.value) return []
  return [.22, .32, .42, .52, .62, .72].map((t) => {
    const inv = 1 - t
    return {
      x: inv * inv * attackerNode.value!.x + 2 * inv * t * geometry.controlX + t * t * targetNode.value!.x,
      y: inv * inv * attackerNode.value!.y + 2 * inv * t * geometry.controlY + t * t * targetNode.value!.y,
    }
  })
})

const sourceTargetLabel = computed(() => {
  if (props.mode === 'replay') return replaySequence.value == null ? '首次合法报文 · seq —' : `首次合法报文 · seq ${replaySequence.value}`
  if (props.mode === 'eavesdropping') return props.encrypted ? '加密业务通信 · AES-GCM' : '业务通信'
  if (props.mode === 'fdi') return onPathFdi.value ? '已认证原帧 → 受控中继' : '合法遥测 · HMAC 认证'
  if (props.mode === 'dos') return '正常业务流'
  if (props.mode === 'spoofing') return '合法原报文'
  return '正常通信'
})

function nodeAction(node: SemanticNode): string | null {
  return node.id === layout.value.targetId ? action.value : null
}
</script>

<template>
  <div class="topology-wrap" :class="[`mode-${mode}`, { 'is-running': isRunning }]">
    <svg v-if="nodes.length" viewBox="0 0 760 380" role="img" :aria-label="`${mode} 场景语义拓扑`">
      <title>节点位置用于展示通信关系，不按实际物理距离比例绘制。</title>
      <defs>
        <pattern :id="`${markerPrefix}-grid`" width="26" height="26" patternUnits="userSpaceOnUse">
          <path d="M26 0H0V26" fill="none" stroke="#dfe8f4" stroke-width="1" opacity=".58" />
        </pattern>
        <marker :id="`${markerPrefix}-blue-arrow`" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0 0 7 3 0 6Z" fill="#4c91e8" /></marker>
        <marker :id="`${markerPrefix}-red-arrow`" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0 0 7 3 0 6Z" fill="#df4b59" /></marker>
        <marker :id="`${markerPrefix}-amber-arrow`" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0 0 7 3 0 6Z" fill="#dd8c29" /></marker>
        <filter id="topology-node-shadow" x="-60%" y="-60%" width="220%" height="220%"><feDropShadow dx="0" dy="4" stdDeviation="4" flood-color="#18395f" flood-opacity=".13" /></filter>
      </defs>

      <rect class="grid-background" x="1" y="1" width="758" height="378" rx="11" :fill="`url(#${markerPrefix}-grid)`" />
      <g v-if="layout.airGroundDividerY" class="semantic-zones">
        <text x="24" y="31">空中编队 / AIR</text>
        <path :d="`M18 ${layout.airGroundDividerY}H742`" />
        <text x="24" :y="layout.airGroundDividerY + 24">地面系统 / GROUND</text>
      </g>

      <g class="normal-edges">
        <path
          v-if="mode !== 'overview' && primaryGeometry && layout.primaryFlow"
          :d="primaryGeometry.path"
          class="normal-edge primary primary-business-flow"
          :data-source-id="layout.primaryFlow.sourceId"
          :data-target-id="onPathFdi ? layout.attackerId : layout.primaryFlow.targetId"
          :data-logical-target-id="layout.primaryFlow.targetId"
          :marker-end="`url(#${markerPrefix}-blue-arrow)`"
        />
        <template v-for="(link, index) in normalLinks" :key="link.id">
          <path
            v-if="normalGeometry(link, index)"
            :d="normalGeometry(link, index)!.path"
            class="normal-edge"
            :class="{
              context: mode !== 'overview',
              blocked: link.status !== 'active',
            }"
          />
        </template>
      </g>

      <g v-if="primaryGeometry && mode !== 'overview'" class="legal-flow-label" :transform="`translate(${primaryGeometry.labelX - (mode === 'fdi' && !externalFdi ? 110 : 0)},${primaryGeometry.labelY + (mode === 'spoofing' || copyFdi ? 20 : -18)})`">
        <rect :x="mode === 'eavesdropping' && encrypted ? -150 : mode === 'fdi' && !externalFdi ? -75 : -112" y="-14" :width="mode === 'eavesdropping' && encrypted ? 300 : mode === 'fdi' && !externalFdi ? 150 : 224" height="28" rx="11" />
        <path v-if="mode === 'eavesdropping' && encrypted" class="inline-lock" d="M-136-1v-4a5 5 0 0 1 10 0v4m-12 0h14v11h-14z" />
        <text :x="mode === 'eavesdropping' && encrypted ? 10 : 0" y="4">{{ sourceTargetLabel }}</text>
      </g>

      <g v-if="attackGeometry" class="attack-flow">
        <path :d="attackGeometry.path" class="attack-edge" :marker-end="`url(#${markerPrefix}-red-arrow)`" />
        <g class="edge-label attack-label" :transform="`translate(${attackGeometry.labelX + (mode === 'spoofing' || externalFdi ? 45 : mode === 'replay' ? -180 : 0)},${attackGeometry.labelY + (mode === 'overview' ? -18 : mode === 'dos' ? -55 : mode === 'replay' ? 8 : mode === 'spoofing' || externalFdi ? 65 : 18)})`">
          <rect x="-118" y="-23" width="236" height="46" rx="10" />
          <text class="main" y="-5">{{ attackCopy.main }}</text>
          <text class="technical" y="14">{{ attackCopy.technical }}</text>
        </g>
      </g>

      <g v-if="mode === 'fdi' && !externalFdi && primaryGeometry" class="fdi-injection" :transform="`translate(${primaryGeometry.labelX},${primaryGeometry.labelY})`">
        <path d="M0-18 18 0 0 18-18 0Z" />
        <path class="bolt" d="m3-12-10 13h7l-3 11L8-2H1Z" />
        <g class="edge-label" transform="translate(0,34)"><title>POST_HMAC_PRE_TRANSMISSION · HMAC 生成后发送前修改载荷</title>
          <rect x="-128" y="-23" width="256" height="46" rx="9" />
          <text class="main" y="-2">{{ attackCopy.main }}</text>
          <text class="technical" y="12">{{ attackCopy.technical }}</text>
        </g>
      </g>

      <g v-if="passiveGeometry" class="passive-flow">
        <path :d="passiveGeometry.path" class="passive-edge" :marker-end="`url(#${markerPrefix}-amber-arrow)`" />
        <g class="edge-label passive-label" :transform="`translate(${passiveGeometry.labelX + (mode === 'replay' ? 20 : 0)},${passiveGeometry.labelY - (mode === 'replay' ? 40 : 0)})`">
          <rect x="-65" y="-23" width="130" height="46" rx="10" />
          <text class="main" y="-5">{{ mode === 'eavesdropping' ? '被动监听' : capture ? '已捕获合法报文' : '监听关系（配置）' }}</text>
          <text class="technical" y="14">{{ mode === 'eavesdropping' ? '不发送数据' : capture ? `${capture.capture_time_s.toFixed(1)} s` : '合法链路旁路复制' }}</text>
        </g>
      </g>

      <g v-if="mode === 'dos' && floodPackets.length" class="flood-packets" aria-label="Flooding 报文流视觉符号">
        <rect v-for="(packet, index) in floodPackets" :key="index" :x="packet.x - 7" :y="packet.y - 5" width="14" height="10" rx="2" :style="{ animationDelay: `${index * .08}s` }" />
      </g>

      <g v-if="mode === 'dos' && targetNode" class="gate-label" :transform="`translate(${targetNode.x - 120},${targetNode.y + 95})`">
        <rect x="-55" y="-10" width="110" height="20" rx="10" />
        <text y="3.5">HMAC Gate</text>
      </g>
      <g v-if="mode === 'dos' && observedRate != null && targetNode" class="rate-label" :transform="`translate(${targetNode.x - 145},45)`">
        <rect x="-132" y="-23" width="264" height="46" rx="9" />
        <text class="main" y="-5">{{ detectorNodeLabel }} · 检测到报文洪泛</text>
        <text class="technical" y="14">峰值 {{ receiverPeakRate ?? '—' }} pps · 阈值 {{ thresholdRate ?? '—' }} pps</text>
      </g>

      <g v-if="mode === 'replay' && targetNode && detected" class="result-label" :class="{ 'has-executed-action': action }" :transform="`translate(${targetNode.x},${targetNode.y + 120})`">
        <rect x="-150" y="-23" width="300" height="46" rx="10" />
        <text class="main" y="-5">HMAC {{ replayHmac || '—' }} → {{ replayResult || evidenceReason }}</text>
        <text class="technical" y="14">{{ action || '等待处置证据' }}</text>
      </g>
      <g v-else-if="(mode === 'spoofing' || mode === 'fdi') && targetNode && detected" class="result-label" :class="{ 'has-executed-action': action }" :transform="`translate(${targetNode.x},${targetNode.y + 115})`">
        <rect x="-112" y="-23" width="224" height="46" rx="10" />
        <text class="main" y="-5">{{ evidenceReason || 'AUTH_FAILURE' }}</text>
        <text class="technical" y="14">{{ action || '等待处置证据' }}</text>
      </g>

      <TopologyNode
        v-for="node in nodes"
        :key="node.id"
        :node="node"
        :display-name="mode === 'eavesdropping' && node.id === layout.attackerId ? 'Eve' : undefined"
        :role-label="mode === 'eavesdropping' && node.id === layout.attackerId ? '被动监听者' : undefined"
        :target="node.id === layout.targetId && Boolean(attackPlan)"
        :detected="node.id === layout.targetId && detected"
        :action="nodeAction(node)"
      />
    </svg>

    <div v-else class="empty-state topology-empty">
      <div><strong>等待场景拓扑</strong>创建场景后显示节点与通信关系。</div>
    </div>

    <div v-if="nodes.length" class="topology-legend">
      <span><i class="legend-line normal"></i>正常通信</span>
      <span v-if="showTruth && attackPlan && mode !== 'eavesdropping' && (mode !== 'fdi' || externalFdi)"><i class="legend-line attack"></i>{{ copyFdi || mode === 'spoofing' ? '攻击副本注入' : onPathFdi ? '兼容替换转发' : mode === 'replay' ? '重放发送' : '洪泛发送' }}</span>
        <span v-if="showTruth && mode === 'eavesdropping'"><i class="legend-line passive"></i>被动监听（场景设定）</span>
        <span v-if="showTruth && (['spoofing','replay'].includes(mode) || copyFdi) && passiveGeometry"><i class="legend-line passive"></i>合法报文捕获</span>
      <span v-if="mode === 'fdi' && !externalFdi"><i class="legend-diamond"></i>HMAC 后篡改点</span>
      <span><i class="legend-node legal"></i>合法节点</span>
      <span v-if="showTruth && nodes.some((node) => node.role === 'EXTERNAL')"><i class="legend-node external"></i>攻击节点（场景）</span>
      <span v-if="action"><i class="legend-shield">✓</i>已执行安全处置</span>
    </div>
  </div>
</template>

<style scoped>
.topology-wrap { min-height: 330px; overflow: hidden; border: 1px solid #e3eaf3; border-radius: 12px; background: #fbfdff; }
svg { display: block; width: 100%; height: 340px; }
.mode-overview svg { height: 390px; }
.mode-replay :deep(.semantic-node.is-target .node-name), .mode-replay :deep(.semantic-node.is-target .node-role) { transform: translateX(46px); }
.grid-background { stroke: #e3ebf5; stroke-width: 1; }
.semantic-zones text { fill: #8496ac; font-size: 15px; font-weight: 700; letter-spacing: .08em; }
.semantic-zones path { fill: none; stroke: #bfcde0; stroke-width: 1.2; stroke-dasharray: 6 6; }
.normal-edge { fill: none; stroke: #4c91e8; stroke-width: 2; opacity: .86; }
.normal-edge.context { stroke: #a8c3e4; stroke-width: 1.3; opacity: .38; marker-end: none; }
.normal-edge.primary { stroke-width: 2.5; opacity: 1; }
.normal-edge.blocked { stroke: #a9b4c2; stroke-dasharray: 5 5; }
.attack-edge { fill: none; stroke: #df4b59; stroke-width: 2.4; stroke-dasharray: 8 6; }
.is-running .attack-edge { animation: attack-dash 1.2s linear infinite; }
@keyframes attack-dash { to { stroke-dashoffset: -28; } }
.passive-edge { fill: none; stroke: #dd8c29; stroke-width: 2.2; stroke-dasharray: 6 6; }
.is-running .passive-edge { animation: passive-dash 1.5s linear infinite; }
@keyframes passive-dash { to { stroke-dashoffset: -24; } }
.edge-label rect { fill: rgba(255,255,255,.96); stroke: #e1e8f1; stroke-width: 1; filter: url(#topology-node-shadow); }
.edge-label text, .legal-flow-label text, .gate-label text, .rate-label text, .result-label text { text-anchor: middle; }
.edge-label .main { fill: #c83b49; font-size: 15px; font-weight: 800; }
.edge-label .technical { fill: #9b6870; font: 14px ui-monospace, SFMono-Regular, Consolas, monospace; }
.passive-label rect { fill: #fff9ed; stroke: #ebca8f; }
.passive-label .main { fill: #b46e16; }
.passive-label .technical { fill: #a4814b; }
.legal-flow-label rect { fill: #edf6ff; stroke: #b7d5f7; }
.legal-flow-label text { fill: #3373bd; font-size: 15px; font-weight: 700; }
.inline-lock { fill: none; stroke: #3373bd; stroke-width: 1.5; stroke-linejoin: round; }
.fdi-injection > path:first-child { fill: #fff0f2; stroke: #db4957; stroke-width: 2; filter: url(#topology-node-shadow); }
.fdi-injection .bolt { fill: #db4957; stroke: none; }
.flood-packets rect { fill: #ef6370; stroke: white; stroke-width: 1; filter: url(#topology-node-shadow); }
.is-running .flood-packets rect { animation: packet-pulse .9s ease-in-out infinite alternate; }
@keyframes packet-pulse { to { opacity: .38; transform: translateX(3px); } }
.gate-label rect { fill: #f0f7ff; stroke: #b5d2f4; }
.gate-label text { fill: #2d70bd; font: 14px ui-monospace, SFMono-Regular, Consolas, monospace; font-weight: 700; }
.rate-label rect { fill: #fff7e9; stroke: #edca8f; }
.rate-label .main { fill: #9b641d; font-size: 14px; font-weight: 800; }
.rate-label .technical { fill: #c34450; font-size: 14px; font-weight: 800; }
.result-label rect { fill: #fff1f3; stroke: #edacb4; filter: url(#topology-node-shadow); }
.result-label .main { fill: #c53c4a; font-size: 15px; font-weight: 800; text-anchor: middle; }
.result-label .technical { fill: #718198; font-size: 14px; font-weight: 800; text-anchor: middle; }
.result-label.has-executed-action .technical { fill: #16815a; }
.lock-label rect { fill: #e7f7f2; stroke: #a7ddcb; }
.lock-label path { fill: none; stroke: #168a69; stroke-width: 1.5; stroke-linejoin: round; }
.lock-label text { fill: #14775d; font-size: 15px; font-weight: 800; text-anchor: start; }
.topology-legend { display: flex; flex-wrap: wrap; justify-content: center; gap: 10px 18px; padding: 12px 16px; border-top: 1px solid #e7edf5; color: #718198; background: #fff; font-size: 15px; }
.topology-legend span { display: inline-flex; align-items: center; gap: 6px; }
.legend-line { width: 22px; height: 0; border-top: 2px solid; }
.legend-line.normal { border-color: #4c91e8; }
.legend-line.attack { border-color: #df4b59; border-top-style: dashed; }
.legend-line.passive { border-color: #dd8c29; border-top-style: dashed; }
.legend-node { width: 9px; height: 9px; border-radius: 50%; background: #397fd2; }
.legend-node.external { background: #d94857; }
.legend-diamond { width: 9px; height: 9px; border: 2px solid #d94857; transform: rotate(45deg); background: #fff0f2; }
.legend-shield { display: grid; place-items: center; width: 15px; height: 15px; border-radius: 50%; color: white; background: #168a5b; font-size: 11px; font-style: normal; }
.topology-scale-note { margin: 0; padding: 9px 14px 11px; border-top: 1px solid #edf1f6; color: #8a98aa; background: #fff; font-size: 11px; text-align: center; }
.topology-empty { min-height: 330px; border: 0; border-radius: 0; background-image: linear-gradient(#e7edf5 1px,transparent 1px),linear-gradient(90deg,#e7edf5 1px,transparent 1px); background-size: 26px 26px; }
@media (min-width: 1600px) { svg { height: 355px; }.mode-overview svg { height: 410px; } }
@media (max-width: 700px) { svg,.mode-overview svg { height: 325px; }.topology-scale-note { text-align: left; } }
</style>
