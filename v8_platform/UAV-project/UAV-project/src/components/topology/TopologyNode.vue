<script setup lang="ts">
import { computed } from 'vue'
import type { SemanticNode } from '@/config/topologyLayouts'
import { humanNodeName, humanRoleName } from '@/config/topologyLayouts'

const props = withDefaults(defineProps<{
  node: SemanticNode
  displayName?: string
  roleLabel?: string
  target?: boolean
  detected?: boolean
  action?: string | null
}>(), { target: false, detected: false, action: null })

const normalizedRole = computed(() => String(props.node.role || '').toUpperCase())
const isDrone = computed(() => ['LEADER', 'FOLLOWER', 'EXTERNAL'].includes(normalizedRole.value))
const isGcs = computed(() => normalizedRole.value === 'GCS')
const isServer = computed(() => normalizedRole.value.includes('SERVER') || normalizedRole.value.includes('SRV'))
const title = computed(() => {
  const position = props.node.pos ? `(${props.node.pos.join(', ')})` : '未提供'
  const state = props.node.state ? `；状态 ${props.node.state}` : ''
  return `${props.displayName || humanNodeName(props.node)}；角色 ${props.roleLabel || humanRoleName(props.node)}；仿真坐标 ${position}${state}${props.target ? '；攻击计划目标' : ''}`
})
const actionLabel = computed(() => {
  if (!props.action) return ''
  if (props.action === 'DROP_PACKET') return '✓ DROP'
  if (props.action === 'NO_UPDATE') return '✓ NO UPDATE'
  if (props.action === 'INCREASE_MONITORING') return '✓ MONITOR'
  return `✓ ${props.action.replace(/_/g, ' ')}`
})
</script>

<template>
  <g
    class="semantic-node"
    :class="[
      normalizedRole.toLowerCase(),
      `emphasis-${node.emphasis}`,
      { 'is-target': target, 'has-action': Boolean(action) },
    ]"
    :transform="`translate(${node.x},${node.y})`"
    tabindex="0"
  >
    <title>{{ title }}</title>
    <circle v-if="target" class="target-ring" r="39" />
    <circle class="node-halo" :r="normalizedRole === 'LEADER' ? 33 : 30" />

    <g v-if="isDrone" class="role-icon drone-icon" aria-hidden="true">
      <ellipse cx="-19" cy="-14" rx="10" ry="3.6" />
      <ellipse cx="19" cy="-14" rx="10" ry="3.6" />
      <ellipse cx="-19" cy="14" rx="10" ry="3.6" />
      <ellipse cx="19" cy="14" rx="10" ry="3.6" />
      <path d="M-16-11-7-4M16-11 7-4M-16 11-7 4M16 11 7 4" />
      <rect x="-8" y="-7" width="16" height="14" rx="5" />
      <path d="M-3 7v7h6V7" />
    </g>
    <g v-else-if="isGcs" class="role-icon station-icon" aria-hidden="true">
      <path d="m0-18-17 38h34L0-18Z" />
      <path d="M-10 4h20M-14 13h28M-10-17q-9-8 0-16M10-17q9-8 0-16" />
      <circle cy="-23" r="3.5" />
    </g>
    <g v-else-if="isServer" class="role-icon server-icon" aria-hidden="true">
      <rect x="-18" y="-22" width="36" height="13" rx="3" />
      <rect x="-18" y="-6" width="36" height="13" rx="3" />
      <rect x="-18" y="10" width="36" height="13" rx="3" />
      <path d="M-11-16h4m-4 16h4m-4 16h4M5-16h7M5 0h7M5 16h7" />
    </g>
    <g v-else class="role-icon generic-icon" aria-hidden="true">
      <path d="M-17-15h34v30h-34zM-10-7h20M-10 0h20M-10 7h12" />
    </g>

    <g v-if="target" class="target-chip" transform="translate(-30,-48)">
      <rect width="60" height="17" rx="8.5" />
      <text x="30" y="11.5">配置目标</text>
    </g>
    <g v-if="detected" class="detect-chip" transform="translate(20,-31)">
      <circle r="9" />
      <path d="m-4 0 2.5 2.7L4-3" />
    </g>

    <text class="node-name" y="49">{{ displayName || humanNodeName(node) }}</text>
    <text class="node-role" y="65">{{ roleLabel || humanRoleName(node) }}</text>
    <g v-if="actionLabel" class="action-chip" transform="translate(-43,77)">
      <rect width="86" height="20" rx="9" />
      <text x="43" y="14">{{ actionLabel }}</text>
    </g>
  </g>
</template>

<style scoped>
.semantic-node { cursor: default; outline: none; transition: opacity .18s ease, transform .18s ease; }
.semantic-node.emphasis-context { opacity: .62; }
.semantic-node:hover, .semantic-node:focus-visible { opacity: 1; }
.node-halo { fill: #f5f9ff; stroke: #c9dbf3; stroke-width: 1.6; transition: .18s ease; filter: url(#topology-node-shadow); }
.semantic-node:hover .node-halo, .semantic-node:focus-visible .node-halo { stroke: #4c8cdd; stroke-width: 2.3; }
.semantic-node.leader .node-halo { fill: #eaf3ff; stroke: #8eb8ed; }
.semantic-node.external .node-halo { fill: #fff1f3; stroke: #f0a4ae; }
.semantic-node.gcs .node-halo { fill: #eef8ff; stroke: #91c7ed; }
.role-icon { fill: none; stroke: #2872c9; stroke-width: 2.1; stroke-linecap: round; stroke-linejoin: round; }
.external .role-icon { stroke: #d94857; }
.server .role-icon { stroke: #486b90; }
.node-name, .node-role { text-anchor: middle; paint-order: stroke; stroke: #fff; stroke-width: 3px; stroke-linejoin: round; }
.node-name { fill: #223b5b; font-size: 16px; font-weight: 800; }
.node-role { fill: #73869d; font-size: 14px; }
.external .node-name { fill: #c63c4b; }
.target-ring { fill: none; stroke: #e9973f; stroke-width: 2; stroke-dasharray: 4 4; }
.target-chip rect { fill: #fff1da; stroke: #efc178; stroke-width: 1; }
.target-chip text { fill: #a86009; font-size: 14px; font-weight: 700; text-anchor: middle; }
.detect-chip circle { fill: #e45260; stroke: white; stroke-width: 2; }
.detect-chip path { fill: none; stroke: white; stroke-width: 1.7; stroke-linecap: round; stroke-linejoin: round; }
.action-chip rect { fill: #daf5e8; stroke: #9edcbc; stroke-width: 1; }
.action-chip text { fill: #167a53; font-size: 14px; font-weight: 800; text-anchor: middle; }
</style>
