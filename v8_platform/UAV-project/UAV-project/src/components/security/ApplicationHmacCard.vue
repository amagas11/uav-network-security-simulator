<script setup lang="ts">
import { computed } from 'vue'
import type { ApplicationHmacMetadata } from '@/api'
import StatusBadge from '@/components/common/StatusBadge.vue'
import { humanizeSecurityResult } from '@/utils/runtimeFormat'

const props = defineProps<{
  metadata?: ApplicationHmacMetadata | null
  mode: 'spoofing' | 'fdi'
  originalIdentity?: string
  claimedIdentity?: string
  originalPayload?: string
  modifiedPayload?: string
  onlineResult?: string | null
  action?: string | null
  actionExecuted?: boolean | null
  injectionStage?: string | null
  hmacRecomputed?: boolean | null
}>()

const algorithm = computed(() => props.metadata?.algorithm || 'HMAC-SHA-256-128')
const tagLength = computed(() => {
  const bytes = props.metadata?.tag_length_bytes ?? 16
  return `${bytes * 8} bit / ${bytes} bytes`
})
const keyScope = computed(() => props.metadata?.key_scope || 'PER_LEGITIMATE_DEVICE')
const coveredFields = computed(() => props.metadata?.covered_fields ?? [
  'direction',
  'device_id',
  'message_type',
  'sequence_no',
  'timestamp_ms',
  'payload_length',
  'business_payload',
])
const resultTone = computed(() => {
  if (!props.onlineResult) return 'neutral'
  return props.onlineResult === 'PASS' ? 'success' : 'danger'
})
const verificationLabel = computed(() => props.onlineResult
  ? humanizeSecurityResult(props.onlineResult)
  : '等待在线验证结果')
const actionLabel = computed(() => {
  if (!props.action) return '—'
  return `${props.action} · ${props.actionExecuted === true ? '已执行' : props.actionExecuted === false ? '未执行' : '执行状态 —'}`
})
</script>

<template>
  <article class="panel hmac-card">
    <div class="panel-header">
      <div>
        <span class="source-label source-truth">协议定义 / 场景机制</span>
        <h2 class="panel-title">Application HMAC 身份与完整性校验</h2>
      </div>
      <div class="verification-badge"><StatusBadge :label="verificationLabel" :tone="resultTone" /><code v-if="onlineResult">{{ onlineResult }}</code></div>
    </div>

    <div class="hmac-protocol-grid">
      <div><span>算法</span><strong>{{ algorithm }}</strong></div>
      <div><span>标签长度</span><strong>{{ tagLength }}</strong></div>
      <div><span>密钥范围</span><strong>设备级独立认证密钥</strong><code>{{ keyScope }}</code></div>
      <div><span>密钥材料</span><strong>隐藏，不传给前端</strong></div>
    </div>

    <div class="covered-fields">
      <span>认证字段</span>
      <code v-for="field in coveredFields" :key="field">{{ field }}</code>
    </div>

    <div class="hmac-formula">
      <span>发送端标签计算</span>
      <code>tag = Trunc128(HMAC-SHA256(K_device, canonical_mac_data))</code>
      <small>认证字段按 canonical JSON 编码为 UTF-8；接收端重算并作常量时间比较。</small>
    </div>

    <div class="source-label source-truth">{{ mode === 'fdi' ? '逐报文篡改真值' : '原报文与副本' }}</div>
    <div v-if="mode === 'spoofing'" class="hmac-explanation">
      <div><span>生成 HMAC 时的原始发送身份</span><strong>{{ originalIdentity || '—' }}</strong><small>按原始发送身份生成并携带标签</small></div>
      <b>仅修改 claimed_src_id</b>
      <div><span>报文声明源身份</span><strong>{{ claimedIdentity || '—' }}</strong><small>场景机制：仅修改声明源身份<br />Application HMAC recomputed = {{ hmacRecomputed === true ? 'YES' : hmacRecomputed === false ? 'NO（场景机制）' : '—' }}</small></div>
      <b>接收侧重算</b>
      <div><span class="source-label source-online">在线验证 / SecurityReport</span><strong>{{ onlineResult ? humanizeSecurityResult(onlineResult) : '—' }}</strong><small>{{ onlineResult || '等待在线证据' }}<br />Action: {{ actionLabel }}</small></div>
    </div>
    <div v-else class="hmac-explanation">
      <div><span>原始业务内容</span><strong>{{ originalPayload || '—' }}</strong><small>合法发送端先生成 Application HMAC</small></div>
      <b>HMAC 生成后篡改</b>
      <div><span>攻击副本业务内容</span><strong>{{ modifiedPayload || '—' }}</strong><small>Application HMAC recomputed = {{ hmacRecomputed === true ? 'YES' : hmacRecomputed === false ? 'NO' : '—' }}<br /><code>{{ injectionStage || '—' }}</code></small></div>
      <b>接收侧重算</b>
      <div><span class="source-label source-online">在线验证 / SecurityReport</span><strong>{{ onlineResult ? humanizeSecurityResult(onlineResult) : '—' }}</strong><small>按收到的已修改 payload 计算期望标签<br />{{ onlineResult || '等待在线证据' }} · {{ actionLabel }}</small></div>
    </div>
  </article>
</template>

<style scoped>
.hmac-card { overflow: hidden; }
.hmac-protocol-grid { display: grid; grid-template-columns: repeat(4,minmax(0,1fr)); gap: 9px; margin-bottom: 12px; }
.hmac-protocol-grid > div { min-width: 0; padding: 11px; border: 1px solid #dde5ee; border-radius: 9px; background: #f8fbff; }
.hmac-protocol-grid span,.hmac-protocol-grid strong,.hmac-protocol-grid code { display: block; }
.hmac-protocol-grid span { color: #7b899b; font-size: 11px; }
.hmac-protocol-grid strong { margin-top: 6px; overflow-wrap: anywhere; color: #324a63; font: 12px ui-monospace,monospace; }
.hmac-protocol-grid code { margin-top: 4px; overflow-wrap: anywhere; color: #8996a7; font-size: 10px; }
.covered-fields { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin-bottom: 13px; }
.covered-fields > span { margin-right: 4px; color: #718096; font-size: 10px; }
.covered-fields code { padding: 4px 6px; border-radius: 5px; color: #3c638b; background: #edf5ff; font-size: 11px; }
.verification-badge { display: grid; justify-items: end; gap: 5px; }.verification-badge code { color: #8390a1; font-size: 10px; }
.hmac-formula { display: grid; grid-template-columns: auto minmax(280px,1fr); align-items: center; gap: 7px 12px; margin-bottom: 13px; padding: 10px 12px; border: 1px solid #dce5ef; border-radius: 9px; background: #f8fbff; }
.hmac-formula span { color: #66768a; font-size: 11px; font-weight: 700; }.hmac-formula code { overflow-wrap: anywhere; color: #2e5f96; font-size: 10px; }.hmac-formula small { grid-column: 2; color: #7d8a9b; font-size: 10px; line-height: 1.5; }
.hmac-explanation { display: grid; grid-template-columns: minmax(0,1fr) auto minmax(0,1fr) auto minmax(0,1fr); align-items: center; gap: 8px; }
.hmac-explanation > div { min-width: 0; padding: 12px; border: 1px solid #e1e7ef; border-radius: 9px; background: #fff; }
.hmac-explanation span,.hmac-explanation strong,.hmac-explanation small { display: block; }
.hmac-explanation span { color: #7b899b; font-size: 11px; }
.hmac-explanation strong { margin: 6px 0; overflow-wrap: anywhere; font-size: 12px; }
.hmac-explanation small { color: #79889b; font-size: 11px; line-height: 1.45; }.hmac-explanation small code { overflow-wrap: anywhere; font-size: 10px; }
.hmac-explanation > b { color: #c84755; font-size: 11px; text-align: center; }
@media (max-width: 980px) { .hmac-protocol-grid { grid-template-columns: repeat(2,minmax(0,1fr)); }.hmac-explanation { grid-template-columns: 1fr; }.hmac-explanation > b { padding: 2px 0; }.hmac-formula { grid-template-columns: 1fr; }.hmac-formula small { grid-column: auto; } }
</style>
