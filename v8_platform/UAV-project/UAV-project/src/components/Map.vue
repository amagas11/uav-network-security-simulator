<script setup>
import { computed, ref, watch, nextTick } from "vue";
import MapIcon from "@/components/icons/MapIcon.vue";
import UAVIcon from "@/components/icons/UAVIcon.vue";
import AttackIcon from "@/components/icons/AttackIcon.vue";
import SuccessIcon from "@/components/icons/SuccessIcon.vue";
import NetworkTopology from "@/components/charts/NetworkTopology.vue";

const props = defineProps({
  latestEvent: {
    type: Object,
    default: null,
  },
  sessionInfo: {
    type: Object,
    default: () => ({ attackId: "", running: false }),
  },
  /** AttackControl 在 init 成功后下发，含 nodes / links */
  topologyPayload: {
    type: Object,
    default: null,
  },
  defenseSnapshot: {
    type: Object,
    default: null,
  },
});

const topologyRef = ref(null);
const nodeStatusMap = ref({});
const topologyMode = ref("global");
const battleLogs = ref([]);

const pushBattleLog = (kind, text, seq = null) => {
  const stamp = new Date().toLocaleTimeString("zh-CN", { hour12: false });
  const item = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    kind,
    text,
    seq,
    stamp,
  };
  battleLogs.value = [item, ...battleLogs.value].slice(0, 80);
};

const logTypeLabel = (kind) => {
  if (kind === "attack") return "攻击";
  if (kind === "detection") return "检测";
  if (kind === "defense") return "防御";
  return "系统";
};

const getLogStatusClass = (text) => {
  if (!text) return "";
  if (text.includes("成功") || text.includes("捕获") || text.includes("防御成功率")) return "log-success";
  if (text.includes("未触发") || text.includes("失败") || text.includes("Buffer Empty")) return "log-fail";
  if (text.includes("监听中") || text.includes("启动") || text.includes("进度") || text.includes("干扰开始")) return "log-progress";
  return "";
};

const formatCommand = (cmd) => {
  if (!cmd || typeof cmd !== "object") return "-";
  const name = cmd.cmd || cmd.name || "CMD";
  const params = cmd.params ? JSON.stringify(cmd.params) : "";
  return params ? `${name}${params}` : name;
};

const formatBackendLog = (event) => {
  const log = event.backendLog || {};
  const packet = log.packet || {};
  const secAction = log.defenseAction || event.defenseAction || "N/A";
  const reason = log.defenseReason || "";
  const route = [event.fromNode, event.toNode].filter(Boolean).join(" -> ");
  const attackType = log.attackType || props.sessionInfo?.payload?.type || "未知攻击";
  const detail = log.attackDetail || {};
  const detailDesc = detail.desc ? `，详情: ${detail.desc}` : "";
  const signature = packet.signatureStatus ? `，签名: ${packet.signatureStatus}` : "";

  if (attackType === "DoS") {
    const dos = log.dosDetail || {};
    const detected = dos.detected == null ? "" : `，检测${dos.detected ? "成功" : "未触发"}`;
    const rate = dos.packet_rate_pps == null ? "" : `，总到达速率${Number(dos.packet_rate_pps).toFixed(1)}pps`;
    const count = dos.total_packet_count == null ? "" : `，窗口报文${dos.total_packet_count}`;
    const defenseText = dos.defense_enabled == null ? "" : `，防御${dos.defense_enabled ? "ON" : "OFF"}`;
    return `DoS/FLOODING${route ? ` ${route}` : ""}${rate}${count}${detected}${defenseText}，非法报文由HMAC门丢弃，动作: ${secAction}${reason ? `，原因: ${reason}` : ""}`;
  }

  if (attackType === "Eavesdropping") {
    const eav = packet.eavesdropStatus || {};
    const isListening = eav.listener_active ?? false;
    const plain = eav.plaintext_captured ?? 0;
    const enc = eav.encrypted_captured ?? 0;
    const rate = eav.defense_success_rate ?? 0;
    const encrypted = packet.isEncrypted ? "加密" : "明文";
    const phase = isListening ? "监听中" : "已停止";
    const captureText = plain > 0 ? `明文捕获${plain}` : (enc > 0 ? `仅元数据${enc}` : "无捕获");
    return `窃听攻击${route ? ` ${route}` : ""}，${phase}(${encrypted})，${captureText}，防御成功率${rate}%`;
  }

  if (attackType === "FDI") {
    const before = formatCommand(packet.originalCommand);
    const after = formatCommand(packet.command);
    const phase = "注入执行";
    return `FDI${phase}${route ? ` ${route}` : ""}，指令${before}→${after}${signature}，动作: ${secAction}${reason ? `，原因: ${reason}` : ""}${detailDesc}`;
  }

  if (attackType === "Spoofing") {
    const claimed = packet.claimedSrc != null ? Number(packet.claimedSrc) + 1 : "-";
    const actual = packet.actualSrc != null ? Number(packet.actualSrc) + 1 : "-";
    return `报文伪装${route ? ` ${route}` : ""}，源${actual}→声明${claimed}${signature}，动作: ${secAction}${reason ? `，原因: ${reason}` : ""}${detailDesc}`;
  }

  if (attackType === "Replay") {
    const seqText = detail.desc ? `，${detail.desc}` : "";
    const buf = packet.replayBufferSize != null ? `，缓冲${packet.replayBufferSize}` : "";
    return `重放攻击${route ? ` ${route}` : ""}${seqText}${buf}${signature}，动作: ${secAction}${reason ? `，原因: ${reason}` : ""}`;
  }

  return `${logTypeLabel(event.eventType)}${route ? `: ${route}` : ""}，动作: ${secAction}${reason ? `，原因: ${reason}` : ""}`;
};

const enterFocusMode = () => {
  const topo = topologyRef.value;
  if (!topo) return;
  topologyMode.value = "focus";
  topo.applyFocusFromPayload(props.sessionInfo?.payload ?? null);
};

const enterGlobalMode = () => {
  const topo = topologyRef.value;
  topologyMode.value = "global";
  topo?.showGlobalTopology();
};

const totalNodes = computed(
  () => props.topologyPayload?.nodes?.length ?? 12,
);

const legendArray = computed(() => {
  const m = nodeStatusMap.value;
  const attackers = Object.values(m).filter((v) => v === "attacker").length;
  const victimLike = Object.values(m).filter((v) =>
    ["victim", "dos_endpoint", "compromised"].includes(v),
  ).length;
  const defended = Object.values(m).filter((v) => v === "defended").length;
  const tagged = Object.keys(m).length;
  const normal = Math.max(0, totalNodes.value - tagged);
  return [
    { value: "正常", number: normal, iconColor: "#CAD5E2" },
    { value: "攻击源", number: attackers, iconColor: "#F97316" },
    { value: "受害/干扰端", number: victimLike, iconColor: "#FB2C36" },
    { value: "已防御", number: defended, iconColor: "#00BC7D" },
  ];
});

const defensePanelRows = computed(() => {
  const cfg = props.defenseSnapshot?.config;
  if (!cfg || typeof cfg !== "object") return [];
  return Object.entries(cfg).map(([type, enabled]) => ({
    type,
    enabled: Boolean(enabled),
  }));
});

watch(
  () => props.latestEvent,
  async (event) => {
    if (!event) return;
    await nextTick();
    const topo = topologyRef.value;
    if (!topo) return;
    topo.applyEvent(event);

    pushBattleLog(event.eventType, formatBackendLog(event), event.seq ?? null);

    // 阶段日志增强：针对 Eavesdropping/Replay/DoS 补充启动/进度/结束提示
    const log = event.backendLog || {};
    const pAtk = log.attackType || props.sessionInfo?.payload?.type;
    if (pAtk === "Eavesdropping") {
      const eav = log.packet?.eavesdropStatus || {};
      const totalCap = (eav.plaintext_captured ?? 0) + (eav.encrypted_captured ?? 0);
      if ((eav.listener_active ?? false) && totalCap === 0) {
        pushBattleLog("system", "窃听监听启动，等待目标报文...", event.seq ?? null);
      }
    }
    if (pAtk === "Replay") {
      const bufLen = log.packet?.replayBufferSize ?? (log.attackDetail?.buffer ?? 0);
      if (bufLen > 0 && event.eventType === "attack") {
        pushBattleLog("system", `重放缓冲已就绪(${bufLen}包)，准备注入`, event.seq ?? null);
      }
    }
    if (pAtk === "DoS") {
      const dos = log.dosDetail || {};
      if (dos.packet_rate_pps != null && event.eventType === "attack") {
        pushBattleLog("system", `DoS/FLOODING总体到达速率 ${Number(dos.packet_rate_pps).toFixed(1)}pps`, event.seq ?? null);
      }
    }

    const { eventType, fromNode, toNode } = event;
    const p = props.sessionInfo?.payload;
    const next = { ...nodeStatusMap.value };

    if (eventType === "attack") {
      if (p?.type === "Eavesdropping" && p.attack_src != null) {
        next[String(Number(p.attack_src) + 1)] = "attacker";
      } else if (p?.attack_src != null || p?.attack_dst != null) {
        if (p?.attack_src != null) {
          next[String(Number(p.attack_src) + 1)] = "attacker";
        }
        if (p?.attack_dst != null) {
          next[String(Number(p.attack_dst) + 1)] = "victim";
        }
      } else {
        if (fromNode) next[fromNode] = "victim";
        if (toNode) next[toNode] = "victim";
      }
    } else if (eventType === "defense") {
      if (p?.type === "Eavesdropping" && p.attack_src != null) {
        next[String(Number(p.attack_src) + 1)] = "defended";
      } else {
        if (fromNode) next[fromNode] = "defended";
        if (toNode) next[toNode] = "defended";
      }
    }

    nodeStatusMap.value = next;
  },
  { deep: true },
);

watch(
  () => props.topologyPayload,
  async (payload) => {
    if (!payload?.nodes?.length) return;
    await nextTick();
    topologyRef.value?.applyTopologyFromServer(payload.nodes, payload.links || []);
    if (topologyMode.value === "focus") {
      topologyRef.value?.applyFocusFromPayload(props.sessionInfo?.payload ?? null);
    }
  },
  { deep: true },
);

watch(
  () => props.sessionInfo?.attackId,
  (attackId, prev) => {
    if (!attackId) {
      nodeStatusMap.value = {};
      enterGlobalMode();
      if (prev) pushBattleLog("system", "本轮攻击会话结束");
      return;
    }
    if (attackId !== prev && topologyRef.value) {
      topologyRef.value.resetState();
      nodeStatusMap.value = {};
      enterFocusMode();
      const p = props.sessionInfo?.payload;
      const attackType = p?.type || "未知";
      const src = p?.attack_src != null ? Number(p.attack_src) + 1 : "-";
      const dst = p?.attack_dst != null ? Number(p.attack_dst) + 1 : "-";
      pushBattleLog("system", `开始攻击: ${attackType}（源:${src}, 目标:${dst}）`);
    }
  },
);
</script>

<template>
    <div class="flex-container">
        <div class="header">
            <div class="title">
                <MapIcon/>
                <span>网络拓扑（{{ topologyMode === "focus" ? "攻击聚焦" : "全局概览" }}）</span>
            </div>

            <div class="legend">
                <button
                    class="mode-btn"
                    :class="{ active: topologyMode === 'global' }"
                    @click="enterGlobalMode"
                >
                    全局
                </button>
                <button
                    class="mode-btn"
                    :class="{ active: topologyMode === 'focus' }"
                    @click="enterFocusMode"
                >
                    聚焦
                </button>
                <div 
                    v-for="item in legendArray"
                    :key="item.value"
                    class="legend-item"
                    >
                    <span
                        class="legend-dot"
                        :style="{ backgroundColor: item.iconColor }"
                    ></span>
                    <span>{{ item.value + '(' + item.number + ')'}}</span>
                </div>
            </div>
        </div>
        
         <div class="chart">
            <NetworkTopology
                ref="topologyRef"
                :attack-payload="sessionInfo?.payload ?? null"
                :topology-links="topologyPayload?.links ?? []"
            />
            <div class="defense-panel">
                <div class="panel-title">节点防御状态</div>
                <div class="panel-subtitle">节点 {{ defenseSnapshot?.nodeDisplayId || "-" }}</div>
                <div v-if="defensePanelRows.length" class="defense-list">
                    <div v-for="row in defensePanelRows" :key="row.type" class="defense-row">
                        <span>{{ row.type }}</span>
                        <span :class="['badge', row.enabled ? 'on' : 'off']">{{ row.enabled ? "ON" : "OFF" }}</span>
                    </div>
                </div>
                <div v-else class="panel-empty">暂无节点防御数据</div>
            </div>
         </div>
        
        <div class="panel-container">
          <div class="custom-legend">
            <div class="custom-legend-item">
                <UAVIcon class="icon"/>
                <span>无人机节点</span>
            </div>
            <div class="custom-legend-item">
                <AttackIcon class="icon"/>
                <span>攻击源 / 受害与干扰端</span>
            </div>
            <div class="custom-legend-item">
                <SuccessIcon class="icon"/>
                <span>防御成功</span>
            </div>
          </div>

          <div class="log-panel">
            <div class="panel-title">攻击/防御日志</div>
            <div class="log-list">
                <div v-for="item in battleLogs" :key="item.id" class="log-item">
                    <span :class="['log-kind', `log-kind-${item.kind}`]">{{ logTypeLabel(item.kind) }}</span>
                    <span class="log-time">[{{ item.stamp }}{{ item.seq != null ? ` #${item.seq}` : "" }}]</span>
                    <span :class="['log-text', getLogStatusClass(item.text)]">{{ item.text }}</span>
                </div>
                <div v-if="!battleLogs.length" class="panel-empty">等待事件日志...</div>
            </div>
          </div>
        </div>
        
    </div>
</template>

<style scoped>
    .flex-container {
        display: flex;
        flex-direction: column;
        gap: 1rem;
        margin: 1.5rem;
    }

    .header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        /* margin-bottom: 0.5rem; */
    }

    .title {
        display: flex;
        flex-direction: row;
        align-items: center;
        color: #fff;
        font-size: larger;
        gap: 0.5rem;
    }

    .legend {
        display: flex;
        gap: 0.5rem;
        font-size: medium;
        color: #CAD5E2;
    }

    .legend-item {
        display: flex;
        flex-direction: row;
        align-items: center;
        gap: 0.5rem;
    }

    .mode-btn {
        background-color: #1D293D;
        border: 1px solid #475569;
        color: #94A3B8;
        border-radius: 6px;
        padding: 0.2rem 0.55rem;
        cursor: pointer;
    }

    .mode-btn.active {
        border-color: #00BC7D;
        color: #E2E8F0;
    }

    .legend-dot {
        width: 1rem;
        height: 1rem;
        border-radius: 50%;
    }

    .chart {
        background-color: #1D293D;
        border: solid #28364C;
        border-width: thin;
        border-radius: 10px;
        padding: 1rem;
        position: relative;
    }

    .defense-panel {
        position: absolute;
        right: 1rem;
        top: 1rem;
        width: 14rem;
        background: rgba(15, 23, 43, 0.85);
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 0.6rem 0.75rem;
        color: #cbd5e1;
    }

    .panel-container {
        display: flex;
        align-items: center;
        justify-content: space-between;
        /* margin-bottom: 0.5rem; */
    }

    .log-panel {
        /* position: absolute; */
        right: 1rem;
        bottom: 1rem;
        width: 22rem;
        height: 11rem;
        background: rgba(15, 23, 43, 0.88);
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 0.6rem 0.75rem;
        color: #cbd5e1;
        box-sizing: border-box;
    }

    .panel-title {
        color: #f8fafc;
        font-size: 0.9rem;
        margin-bottom: 0.3rem;
    }

    .panel-subtitle {
        color: #94a3b8;
        margin-bottom: 0.4rem;
        font-size: 0.82rem;
    }

    .defense-list {
        display: flex;
        flex-direction: column;
        gap: 0.25rem;
    }

    .defense-row {
        display: flex;
        justify-content: space-between;
        font-size: 0.8rem;
    }

    .badge {
        border-radius: 999px;
        padding: 0 0.42rem;
        font-size: 0.75rem;
    }

    .badge.on {
        background: rgba(34, 197, 94, 0.22);
        color: #86efac;
    }

    .badge.off {
        background: rgba(148, 163, 184, 0.2);
        color: #cbd5e1;
    }

    .log-list {
        height: calc(100% - 1.6rem);
        overflow: auto;
        display: flex;
        flex-direction: column;
        gap: 0.22rem;
        font-size: 0.77rem;
        line-height: 1.25;
    }

    .log-item {
        color: #cbd5e1;
        border-left: 2px solid #334155;
        padding-left: 0.3rem;
    }

    .log-time {
        color: #94a3b8;
        margin-right: 0.25rem;
    }

    .log-text {
        color: #e2e8f0;
        white-space: normal;
        word-break: break-word;
    }

    .log-text.log-success {
        color: #86efac;
    }

    .log-text.log-fail {
        color: #fca5a5;
    }

    .log-text.log-progress {
        color: #fcd34d;
    }

    .log-kind {
        display: inline-block;
        margin-right: 0.3rem;
        min-width: 2rem;
        text-align: center;
        border-radius: 4px;
        font-size: 0.7rem;
        line-height: 1.2rem;
        vertical-align: middle;
    }

    .log-kind-attack {
        background: rgba(239, 68, 68, 0.2);
        color: #fca5a5;
    }

    .log-kind-detection {
        background: rgba(245, 158, 11, 0.2);
        color: #fcd34d;
    }

    .log-kind-defense {
        background: rgba(34, 197, 94, 0.2);
        color: #86efac;
    }

    .log-kind-system {
        background: rgba(59, 130, 246, 0.2);
        color: #93c5fd;
    }

    .panel-empty {
        color: #94a3b8;
        font-size: 0.78rem;
    }

    .custom-legend { 
        display: flex;
        flex-direction: column;
        width: fit-content;
        background-color: #1D293D;
        border: solid #28364C;
        border-width: thin;
        border-radius: 10px;
        padding: 1rem 1.5rem 1rem 1rem;
        gap: 1rem;
    }

    .custom-legend-item {
        display: flex;
        align-items: center;
        color: #CAD5E2;
        gap: 0.5rem;
    }

    .icon {
        width: 1.5rem;
        height: 1.5rem;
    }
</style>
