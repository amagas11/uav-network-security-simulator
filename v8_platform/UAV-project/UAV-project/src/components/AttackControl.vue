<script setup>
import { ref, computed, watch, onBeforeUnmount } from "vue";
import AttackControlIcon from "@/components/icons/AttackControlIcon.vue";
import PacketIcon from "@/components/icons/PacketIcon.vue";
import SniffIcon from "@/components/icons/SniffIcon.vue";
import DdosIcon from "@/components/icons/DdosIcon.vue";
import FdiIcon from "@/components/icons/FdiIcon.vue";
import ReplayIcon from "@/components/icons/ReplayIcon.vue";
import {
  initSimulation,
  startAttack as apiStartAttack,
  getRuntime,
  getTopology,
  getCommands,
  getDefenseStatus,
  configDefenseNode,
  configDefenseNodeBatch,
  configDefenseGlobal,
  startListen,
  stopListen,
} from "@/api";

const emit = defineEmits([
  "topology-event",
  "metrics-update",
  "evaluation-update",
  "session-update",
  "topology-sync",
  "defense-node-update",
]);

const attackTypes = [
  { value: "Spoofing", label: "报文伪装", icon: PacketIcon },
  { value: "Eavesdropping", label: "窃听攻击", icon: SniffIcon },
  { value: "DoS", label: "DoS攻击", icon: DdosIcon },
  { value: "FDI", label: "FDI攻击", icon: FdiIcon },
  { value: "Replay", label: "重放攻击", icon: ReplayIcon },
];

const numUavs = 12;
const nodes = Array.from({ length: numUavs }, (_, i) => i + 1);
const links = ref([{ value: "", label: "加载中…" }]);

const selectedAttack = ref(attackTypes[0].value);
const attackNode = ref("");
const targetNode = ref("");
const statusText = ref("请选择攻击参数并发起攻击");
const currentSessionId = ref("");
const polling = ref(false);
const initialized = ref(false);
const preparingTopology = ref(false);
/** GET /api/commands，用于 FDI 指令下拉 */
const fdiCommands = ref(/** @type {Record<string, unknown> | null} */ (null));
const fdiMaliciousCmd = ref("LAND");
const fdiParamsText = ref('{"alt": 0, "mode": "emergency_crash"}');
const defenseTypes = ["Spoofing", "FDI", "Replay", "DoS", "Eavesdropping"];
const selectedDefenseNode = ref("1");
const nodeDefenseConfig = ref({
  Spoofing: false,
  FDI: false,
  Replay: false,
  DoS: false,
  Eavesdropping: false,
});

let stepTimer = null;
let sessionSeed = 0;
let recoverSeen = false;
/** 本轮攻击会话的步进累计（用于指标与成功率） */
let sessionAcc = null;
const MAX_STEPS = 120;
const STEPS_AFTER_ATTACK = 55;
let stepsAfterAttack = 0;
let attackPhaseSeen = false;

const canStart = computed(() => {
  if (!selectedAttack.value || !attackNode.value) return false;
  if (["Spoofing", "FDI", "Replay", "DoS"].includes(selectedAttack.value)) return !!targetNode.value;
  return true;
});

function emptyDefenseConfig() {
  return {
    Spoofing: false,
    FDI: false,
    Replay: false,
    DoS: false,
    Eavesdropping: false,
  };
}

function normalizeNodeDefenseConfig(config) {
  const next = emptyDefenseConfig();
  if (!config || typeof config !== "object") return next;
  for (const attackType of defenseTypes) {
    next[attackType] = Boolean(config?.[attackType]);
  }
  return next;
}

function emitDefenseNodeUpdate(nodeDisplayId = selectedDefenseNode.value, config = nodeDefenseConfig.value) {
  emit("defense-node-update", {
    nodeDisplayId: String(nodeDisplayId || ""),
    nodeBackendId: toBackendNodeId(nodeDisplayId),
    config: { ...config },
    ts: Date.now(),
  });
}

function getDefenseNodeForCurrentAttack() {
  if (["Spoofing", "FDI", "Replay", "DoS"].includes(selectedAttack.value)) {
    return targetNode.value ? String(targetNode.value) : "";
  }
  if (selectedAttack.value === "Eavesdropping") {
    // 窃听防御是发送方加密，因此仍跟随被保护的发送节点。
    return attackNode.value ? String(attackNode.value) : "";
  }
  return "";
}

function syncDefenseNodeWithAttackTarget() {
  const nextNode = getDefenseNodeForCurrentAttack();
  if (!nextNode || selectedDefenseNode.value === nextNode) return;
  selectedDefenseNode.value = nextNode;
}

watch(selectedAttack, async (value) => {
  if (!["Spoofing", "FDI", "Replay", "DoS"].includes(value)) targetNode.value = "";
  syncDefenseNodeWithAttackTarget();
});

watch(selectedDefenseNode, async (nodeDisplayId) => {
  if (!nodeDisplayId || !initialized.value) return;
  await syncNodeDefenseStatus(nodeDisplayId);
});

watch([attackNode, targetNode], syncDefenseNodeWithAttackTarget);

/** 后端节点 id 为 0..numUavs-1，表单为 1..numUavs */
const toBackendNodeId = (displayId) => Number(displayId) - 1;

const buildPayload = () => {
  const src = toBackendNodeId(attackNode.value);
  const payload = {
    type: selectedAttack.value,
    attack_src: src,
  };

  if (["Spoofing", "FDI", "Replay", "DoS"].includes(selectedAttack.value)) {
    payload.attack_dst = toBackendNodeId(targetNode.value);
  }
  if (selectedAttack.value === "DoS") payload.subtype = "FLOODING";

  if (selectedAttack.value === "Spoofing") {
    const alt = src === 0 ? 1 : 0;
    payload.fake_src = alt;
  }
  if (selectedAttack.value === "FDI") {
    payload.malicious_cmd = fdiMaliciousCmd.value;
    try {
      const parsed = JSON.parse(fdiParamsText.value || "{}");
      payload.malicious_params =
        parsed && typeof parsed === "object" ? parsed : {};
    } catch {
      throw new Error("FDI 参数须为合法 JSON 对象");
    }
  }
  return payload;
};

/**
 * 旧版响应映射器；当前主界面改用只读 runtime 视图。
 */
function mapStepToUi(raw, acc, activeAttackType = selectedAttack.value) {
  if (!raw || raw.status === "error") {
    return { error: raw?.msg || "仿真步进失败" };
  }

  const pkt = raw.packet || {};
  const sec = raw.security || {};
  const phy = raw.phy_result || raw.phy || {};
  const netPerf = raw.network_performance || {};
  const throughputSummary = netPerf.throughput_summary || {};
  const latencySummary = netPerf.latency_summary || {};
  const packetLossSummary = netPerf.packet_loss_summary || {};
  const src = pkt.actual_src ?? pkt.src;
  const dst = pkt.actual_dst ?? pkt.dst;
  const fromNode = src != null ? String(Number(src) + 1) : "";
  const toNode = dst != null ? String(Number(dst) + 1) : "";
  const rawDef = String(sec.defense_action || "");
  const dosDetail = sec.dos_detail || {};
  const dstDefenseConfig = sec.dst_defense_config || {};
  const dosDefenseEnabled = Boolean(dosDetail.defense_enabled ?? dstDefenseConfig.DoS);
  const dosDetected = Boolean(
    dosDetail.detected ||
    Number(dosDetail.packet_rate_pps ?? 0) >= Number(dosDetail.threshold_pps ?? 8),
  );
  let def = rawDef;
  let defenseReason = sec.defense_reason;
  let detectionTriggered = Boolean(sec.detection_triggered);

  const normalizedDosDetail = sec.attack_type === "DoS"
    ? {
        ...dosDetail,
        detected: dosDetected,
        defense_enabled: dosDefenseEnabled,
        defense_mechanism: "APPLICATION_HMAC_GATE",
      }
    : dosDetail;
  const backendLog = {
    attackType: sec.attack_type,
    attackDetail: sec.attack_detail,
    attackSuccess: sec.attack_success,
    detectionTriggered,
    detectionEvidence: sec.detection_evidence,
    defenseAction: def,
    defenseReason,
    dstDefenseConfig,
    dosDetail: normalizedDosDetail,
    packet: {
      actualSrc: pkt.actual_src,
      actualDst: pkt.actual_dst,
      claimedSrc: pkt.claimed_src,
      claimedDst: pkt.claimed_dst,
      command: pkt.command,
      originalCommand: pkt.original_command,
      isEncrypted: pkt.is_encrypted,
      signatureStatus: pkt.signature_status,
      encryptionDetail: pkt.encryption_detail,
      eavesdropStatus: pkt.eavesdrop_status,
    },
    phy: {
      success: phy.success,
      detail: phy.detail,
    },
    channel: raw.channel,
    topology: raw.topology,
  };

  acc.totalPkts += 1;
  if (!phy.success) acc.phyLoss += 1;
  if (sec.is_attacked) acc.framesWithAttack += 1;
  if (sec.attack_success || def.includes("Missed")) acc.attackSuccess += 1;
  if (def.includes("Drop") || def.includes("Block")) acc.defenseDrops += 1;
  if (def.includes("Switch")) acc.defenseSwitch += 1;
  if (sec.is_attacked) acc.attackStarted = true;

  let topology_event = null;
  const eavesdropDefended = sec.attack_type === "Eavesdropping" && pkt.is_encrypted;
  if (def.includes("Drop") || def.includes("Block") || eavesdropDefended) {
    topology_event = { eventType: "defense", fromNode, toNode, seq: raw.seq, defenseAction: def, backendLog };
  } else if (detectionTriggered) {
    topology_event = { eventType: "detection", fromNode, toNode, seq: raw.seq, defenseAction: def, backendLog };
  } else if (def.includes("Switch")) {
    topology_event = { eventType: "defense", fromNode, toNode, seq: raw.seq, defenseAction: def, backendLog };
  } else if (sec.is_attacked) {
    topology_event = { eventType: "attack", fromNode, toNode, seq: raw.seq, defenseAction: def, backendLog };
  }

  let phase = "idle";
  if (def.includes("Drop") || def.includes("Block") || def.includes("Switch") || eavesdropDefended) phase = "defense";
  else if (detectionTriggered) phase = "detect";
  else if (sec.is_attacked) phase = "attack";
  else if (def.includes("Switch") || def.includes("Pass")) phase = "defense";
  else if (acc.attackStarted && !sec.is_attacked) phase = "recover";

  const throughputPct = Number(throughputSummary.utilization_pct ?? 0);
  const latencyMs = Number(latencySummary.total_ms ?? 0);
  const lossPct = Number(packetLossSummary.total_loss_rate_pct ?? raw?.cumulative_stats?.total_loss_rate_pct ?? 0);
  const metrics = {
    throughput: Math.max(0, Math.min(100, throughputPct)),
    packetLoss: Math.max(0, Math.min(100, lossPct)),
    latency: Math.max(0, latencyMs),
    phase,
  };

  const allRates = raw.attack_metrics || {};
  const focusType = activeAttackType || sec.attack_type || "Spoofing";
  const focusRates = allRates[focusType] || {};
  const attackRate = Number(focusRates.attack_success_rate ?? 0);
  const detectRate = Number(focusRates.detect_success_rate ?? 0);
  const defenseRate = Number(focusRates.defense_success_rate ?? focusRates.detect_success_rate ?? 0);

  const evaluation = {
    attackSuccessRate: Math.max(0, Math.min(1, attackRate / 100)),
    detectionSuccessRate: Math.max(0, Math.min(1, detectRate / 100)),
    defenseSuccessRate: Math.max(0, Math.min(1, defenseRate / 100)),
    phase,
  };

  return {
    seq: raw.seq,
    topology_event,
    metrics,
    evaluation,
    security: {
      ...sec,
      detection_triggered: detectionTriggered,
      defense_action: def,
      defense_reason: defenseReason,
      dos_detail: normalizedDosDetail,
    },
    raw,
  };
}

async function startAttack() {
  if (!canStart.value || polling.value) return;

  stopPolling();
  let payload;
  try {
    payload = buildPayload();
  } catch (e) {
    statusText.value = e?.message || "参数无效";
    return;
  }
    statusText.value = "攻击请求已发送，等待后端响应...";

  try {
    if (!initialized.value) {
      const initRes = await initSimulation(numUavs);
      if (initRes.status !== "initialized") {
        throw new Error(initRes.msg || "仿真环境初始化失败");
      }
      initialized.value = true;
      emit("topology-sync", {
        nodes: initRes.nodes || [],
        links: initRes.links || [],
        num_uavs: numUavs,
      });
      await refreshTopologyOptions();
      await initializeDefenseDefaults();
      await syncNodeDefenseStatus();
    }

    // ★ 修复：Replay / Eavesdropping 需要先启动监听填充缓冲/开始捕获
    if (["Replay", "Eavesdropping"].includes(selectedAttack.value)) {
      statusText.value = `正在启动 ${selectedAttack.value} 监听...`;
      try {
        const listenRes = await startListen(selectedAttack.value, 25);
        if (listenRes.status !== "listening_started") {
          throw new Error(listenRes.msg || "监听启动失败");
        }
        statusText.value = `监听已启动，准备攻击...`;

        // Replay 必须先捕获若干报文才能重放：手动运行几步填充缓冲区
        if (selectedAttack.value === "Replay") {
          statusText.value = "Replay 正在捕获报文以填充缓冲...";
          for (let i = 0; i < 6; i++) {
            try {
              await getRuntime();
              await new Promise((r) => setTimeout(r, 150));
            } catch (_) {
              /* 忽略步进错误，继续尝试 */
            }
          }
          statusText.value = "Replay 缓冲已就绪，发起攻击...";
        }
      } catch (listenErr) {
        statusText.value = `监听启动失败：${listenErr.message}，将直接尝试攻击`;
      }
    }

    const res = await apiStartAttack(payload);
    if (res.status !== "queued") {
      throw new Error(res.msg || "攻击请求被拒绝");
    }

    sessionSeed += 1;
    recoverSeen = false;
    attackPhaseSeen = false;
    stepsAfterAttack = 0;
    sessionAcc = {
      totalPkts: 0,
      phyLoss: 0,
      framesWithAttack: 0,
      attackSuccess: 0,
      defenseDrops: 0,
      defenseSwitch: 0,
      attackStarted: false,
    };
    currentSessionId.value = `sim-${sessionSeed}`;
    polling.value = true;
    statusText.value = `攻击任务已入队（${selectedAttack.value}）`;
    emit("session-update", { attackId: currentSessionId.value, running: true, payload });
    startPolling();
  } catch (error) {
    statusText.value = `发起失败：${error.message}`;
    polling.value = false;
    currentSessionId.value = "";
    emit("session-update", { attackId: "", running: false, error: error.message });
  }
}

async function refreshTopologyOptions() {
  try {
    links.value = [{ value: "", label: "加载中…" }];
    const topo = await getTopology();
    if (topo.status === "success" && Array.isArray(topo.links) && topo.links.length) {
      links.value = topo.links.map((l) => ({
        value: l.id,
        src: l.src,
        dst: l.dst,
        label: `链路 ${l.id}（${l.src}→${l.dst}）`,
      }));
    } else {
      links.value = [{ value: "", label: "暂无可用链路" }];
    }
  } catch (e) {
    links.value = [{ value: "", label: "链路加载失败" }];
    throw e;
  }
}

async function ensureInitializedForDefense() {
  if (initialized.value) return;
  statusText.value = "正在初始化仿真环境...";
  const initRes = await initSimulation(numUavs);
  if (initRes.status !== "initialized") {
    throw new Error(initRes.msg || "仿真环境初始化失败");
  }
  initialized.value = true;
  emit("topology-sync", {
    nodes: initRes.nodes || [],
    links: initRes.links || [],
    num_uavs: numUavs,
  });
  await refreshTopologyOptions();
  await initializeDefenseDefaults();
}

async function initializeDefenseDefaults() {
  for (const attackType of defenseTypes) {
    await configDefenseGlobal(attackType, false);
  }
}

async function syncNodeDefenseStatus(nodeDisplayId = selectedDefenseNode.value) {
  const nodeId = toBackendNodeId(nodeDisplayId);
  if (Number.isNaN(nodeId) || nodeId < 0) return;
  try {
    const res = await getDefenseStatus(nodeId);
    if (res?.status === "success") {
      nodeDefenseConfig.value = normalizeNodeDefenseConfig(res.defense_config);
      emitDefenseNodeUpdate(nodeDisplayId, nodeDefenseConfig.value);
    }
  } catch {
    nodeDefenseConfig.value = emptyDefenseConfig();
    emitDefenseNodeUpdate(nodeDisplayId, nodeDefenseConfig.value);
  }
}

async function toggleNodeDefense(type) {
  if (!defenseTypes.includes(type) || polling.value) return;
  try {
    await ensureInitializedForDefense();
    const nodeId = toBackendNodeId(selectedDefenseNode.value);
    if (Number.isNaN(nodeId) || nodeId < 0) {
      statusText.value = "请先选择有效的防御节点";
      return;
    }
    const nextEnabled = !Boolean(nodeDefenseConfig.value[type]);
    const res = await configDefenseNode(nodeId, type, nextEnabled);
    if (res?.status !== "success") {
      throw new Error(res?.msg || "节点防御配置更新失败");
    }
    nodeDefenseConfig.value = {
      ...nodeDefenseConfig.value,
      [type]: nextEnabled,
    };
    emitDefenseNodeUpdate(selectedDefenseNode.value, nodeDefenseConfig.value);
    statusText.value = `节点 ${selectedDefenseNode.value} 的 ${type} 防御已${nextEnabled ? "开启" : "关闭"}`;
  } catch (e) {
    statusText.value = `节点防御配置失败：${e?.message || "未知错误"}`;
  }
}

async function disableAllDefenseForNode() {
  if (polling.value) return;
  try {
    await ensureInitializedForDefense();
    const nodeId = toBackendNodeId(selectedDefenseNode.value);
    if (Number.isNaN(nodeId) || nodeId < 0) {
      statusText.value = "请先选择有效的防御节点";
      return;
    }
    const config = Object.fromEntries(defenseTypes.map((type) => [type, false]));
    const res = await configDefenseNodeBatch(nodeId, config);
    if (res?.status !== "success") {
      throw new Error(res?.msg || "节点防御清空失败");
    }
    nodeDefenseConfig.value = emptyDefenseConfig();
    emitDefenseNodeUpdate(selectedDefenseNode.value, nodeDefenseConfig.value);
    statusText.value = `节点 ${selectedDefenseNode.value} 防御已全部关闭`;
  } catch (e) {
    statusText.value = `清空节点防御失败：${e?.message || "未知错误"}`;
  }
}

async function ensureTopologyReadyForDos() {
  if (preparingTopology.value) return;
  preparingTopology.value = true;
  try {
    if (!initialized.value) {
      statusText.value = "正在初始化仿真并加载链路...";
      const initRes = await initSimulation(numUavs);
      if (initRes.status !== "initialized") {
        throw new Error(initRes.msg || "仿真环境初始化失败");
      }
      initialized.value = true;
      emit("topology-sync", {
        nodes: initRes.nodes || [],
        links: initRes.links || [],
        num_uavs: numUavs,
      });
    }
    await refreshTopologyOptions();
    await syncNodeDefenseStatus();
    statusText.value = "请选择攻击参数并发起攻击";
  } catch (error) {
    statusText.value = `链路准备失败：${error.message}`;
  } finally {
    preparingTopology.value = false;
  }
}

function startPolling() {
  stepTimer = setInterval(async () => {
    if (!currentSessionId.value) return;
    try {
      const raw = await getRuntime();
      if (raw.status === "error") {
        throw new Error(raw.msg || "仿真未运行");
      }

      const mapped = mapStepToUi(raw, sessionAcc, selectedAttack.value);
      if (mapped.error) throw new Error(mapped.error);

      if (mapped.topology_event) {
        emit("topology-event", mapped.topology_event);
      }
      if (mapped.metrics) {
        emit("metrics-update", {
          throughput: mapped.metrics.throughput,
          packetLoss: mapped.metrics.packetLoss,
          latency: mapped.metrics.latency,
          phase: mapped.metrics.phase,
        });
      }
      if (mapped.evaluation) {
        emit("evaluation-update", {
          attackSuccessRate: mapped.evaluation.attackSuccessRate,
          detectionSuccessRate: mapped.evaluation.detectionSuccessRate,
          defenseSuccessRate: mapped.evaluation.defenseSuccessRate,
          phase: mapped.evaluation.phase,
        });
      }

      if (mapped.security?.is_attacked) {
        attackPhaseSeen = true;
      }
      if (attackPhaseSeen) stepsAfterAttack += 1;
      if (mapped.evaluation?.phase === "recover") recoverSeen = true;

      const def = mapped.security?.defense_action || "None";
      statusText.value = `当前帧: ${mapped.seq}，防御: ${def}`;

      const totalSteps = mapped.seq ?? 0;
      const doneBySteps =
        attackPhaseSeen &&
        (stepsAfterAttack >= STEPS_AFTER_ATTACK || totalSteps >= MAX_STEPS);
      if (doneBySteps) {
        statusText.value = `攻击演示完成（约 ${mapped.seq} 帧）`;
        stopPolling(false);
      }
    } catch (error) {
      statusText.value = `仿真步进失败：${error.message}`;
      stopPolling();
    }
  }, 1000);
}

function stopPolling(resetSession = true) {
  if (stepTimer) clearInterval(stepTimer);
  stepTimer = null;
  polling.value = false;
  sessionAcc = null;
  stepsAfterAttack = 0;
  attackPhaseSeen = false;

  // 清理监听状态（Replay/Eavesdropping）
  if (["Replay", "Eavesdropping"].includes(selectedAttack.value)) {
    stopListen(selectedAttack.value).catch(() => {});
  }

  if (resetSession) {
    currentSessionId.value = "";
    emit("session-update", { attackId: "", running: false });
  } else {
    emit("session-update", { attackId: currentSessionId.value, running: false });
  }
}

onBeforeUnmount(() => {
  stopPolling();
});

async function loadFdiCommands() {
  try {
    const res = await getCommands();
    if (res.status === "success" && res.commands) {
      fdiCommands.value = res.commands;
      const keys = Object.keys(res.commands);
      if (keys.length && !keys.includes(fdiMaliciousCmd.value)) {
        fdiMaliciousCmd.value = keys[0];
      }
      syncFdiExampleParams();
    }
  } catch {
    fdiCommands.value = null;
  }
}

function syncFdiExampleParams() {
  const t = fdiCommands.value?.[fdiMaliciousCmd.value];
  const ex = t?.example?.params;
  if (ex) {
    fdiParamsText.value = JSON.stringify(ex);
  }
}

watch(fdiMaliciousCmd, () => {
  syncFdiExampleParams();
});

loadFdiCommands();
</script>

<template>
    <div class="flex_container">
        <!--标题区域-->
        <div class="title">
            <AttackControlIcon/>
            <span>攻击控制</span>
        </div>

        <!--区块标题-->
        <div class="section-title">选择攻击类型</div>

        <!--攻击类型选择区域-->
        <div class="attack-list">
            <!--把 attackTypes 里的每一项都变成一个 button-->
            <button
                v-for="item in attackTypes"
                :key="item.value"
                class="attack-btn"
                :class="{ active: item.value === selectedAttack }"
                @click="selectedAttack = item.value"
            >
                <component :is="item.icon" class="icon"/>
                <span>{{ item.label }}</span>
            </button>
        </div>

        <div class="section-title">节点防御开关（默认全关）</div>
        <select
            v-model="selectedDefenseNode"
            class="select selected"
            :disabled="polling"
        >
            <option v-for="n in nodes" :key="`def-${n}`" :value="String(n)">节点 {{ n }}</option>
        </select>
        <div class="defense-grid">
            <button
                v-for="dtype in defenseTypes"
                :key="dtype"
                class="defense-btn"
                :class="{ active: nodeDefenseConfig[dtype] }"
                :disabled="polling"
                @click="toggleNodeDefense(dtype)"
            >
                <span>{{ dtype }}</span>
                <span>{{ nodeDefenseConfig[dtype] ? "ON" : "OFF" }}</span>
            </button>
        </div>
        <button
            class="defense-reset-btn"
            :disabled="polling"
            @click="disableAllDefenseForNode"
        >
            关闭该节点全部防御
        </button>

        <!-- 攻击节点（永远需要） -->
        <div class="section-title">选择攻击节点</div>
        <select 
            v-if="selectedAttack" 
            v-model="attackNode" 
            :class="['select', { selected: attackNode }]">
            <option value="">请选择攻击节点</option>
            <option v-for="n in nodes" :key="n" :value="n">{{ n }}</option>
        </select>


        <!--① 报文伪装、FDI攻击、重放攻击：目标节点-->
        <template
            v-if="['Spoofing', 'FDI', 'Replay'].includes(selectedAttack)"
        >
            <div class="section-title">选择目标节点</div>

            <select 
                v-model="targetNode" 
                :class="['select', { selected: attackNode }]">
                <option value="">请选择目标节点</option>
                <option v-for="n in nodes" :key="n" :value="n">{{ n }}</option>
            </select>

            <!-- FDI：恶意指令（POST /api/attack 与 GET /api/commands） -->
            <template v-if="selectedAttack === 'FDI'">
                <div class="section-title">恶意指令</div>
                <select
                    v-model="fdiMaliciousCmd"
                    class="select selected"
                    @change="syncFdiExampleParams"
                >
                    <option
                        v-for="cmd in Object.keys(fdiCommands || {})"
                        :key="cmd"
                        :value="cmd"
                    >
                        {{ cmd }}
                    </option>
                    <option v-if="!fdiCommands" value="LAND">LAND（默认）</option>
                </select>
                <div class="section-title">参数 JSON</div>
                <textarea
                    v-model="fdiParamsText"
                    class="json-area"
                    rows="4"
                    spellcheck="false"
                />
            </template>
        </template>

        <!--② DoS/Flooding：按接收节点总体到达速率检测-->
        <template v-else-if="selectedAttack === 'DoS'">
            <div class="section-title">选择接收节点</div>
            <select v-model="targetNode" :class="['select', { selected: targetNode }]">
                <option value="">请选择接收节点</option>
                <option v-for="node in nodes" :key="node" :value="node">UAV-{{ node }}</option>
            </select>
            <p class="tip">FLOODING 按该节点所有来源的总体报文速率检测；非法报文由应用 HMAC 门前置丢弃。</p>
        </template>

        <!--③ 窃听攻击：不需要额外选择-->
        <template v-else-if="selectedAttack === 'Eavesdropping'">
            <p class="tip">
                窃听攻击无需选择目标，只需确定攻击节点。
            </p>
        </template>

        <!-- 发起攻击 -->
        <button 
            class="action-btn"
            :disabled="!canStart || polling"
            :class="{ active: canStart && !polling }"
            @click="startAttack">
            ▶ 发起攻击
        </button>

        <p class="tip">{{ statusText }}</p>
    </div>
</template>

<style scoped>
    .flex_container {
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
        margin: 1.5rem;
    }

    .title {
        display: flex;
        align-items: center;
        color: #fff;
        font-size: larger;
        gap: 0.5rem;
        margin-bottom: 0.5rem;
    }
    
    .section-title {
        color: #90A1B9;
        font-size: large;
    }

    .attack-list {
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
        margin-bottom: 0.5rem;
    }

    .defense-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 0.4rem;
        margin-bottom: 0.5rem;
    }

    .defense-btn {
        display: flex;
        justify-content: space-between;
        align-items: center;
        background-color: #1D293D;
        color: #94A3B8;
        border: 1px solid #314158;
        border-radius: 8px;
        padding: 0.4rem 0.55rem;
        font-size: 0.85rem;
    }

    .defense-btn.active {
        border-color: #00BC7D;
        color: #E2E8F0;
    }

    .defense-reset-btn {
        background-color: #1D293D;
        color: #CBD5E1;
        border: 1px solid #475569;
        border-radius: 8px;
        padding: 0.45rem 0.6rem;
        margin-bottom: 0.5rem;
    }

    .attack-btn {
        display: flex;
        align-items: center;
        background-color: #1D293D;
        color: #899AB1;
        font-size: medium;
        text-align: start;
        padding: 0.5rem;
        gap: 0.5rem;
        border: solid transparent;
        border-radius: 10px;
    }

    .attack-btn.active {
        border-color: #EF4444;
        color: #fff;
    }

    .icon {
        width: 1rem;
        height: 1rem;
    }

    .select {
        background: #1D293D;
        color: #899AB1;
        border: solid #62748E;
        border-width: thin;
        border-radius: 5px;
        font-size: 1rem;
        padding: 0.5rem;
        margin-bottom: 0.5rem;
    }

    .select.selected {
        color: #fff;
        font-weight: 500;
        border: solid #fff;
        /* border-width: thin; */
        border-radius: 5px;
    }
    
    .action-btn {
        background-color: #314158;
        color: #62748E;
        font-size: larger;
        padding: 1rem;
        border: none;
        border-radius: 10px;
    }

    .action-btn.active {
        background-color: #009966;
        color: #fff;
    }

    .json-area {
        width: 100%;
        box-sizing: border-box;
        background: #1d293d;
        color: #e2e8f0;
        border: thin solid #62748e;
        border-radius: 5px;
        font-family: ui-monospace, monospace;
        font-size: 0.85rem;
        padding: 0.5rem;
        margin-bottom: 0.5rem;
        resize: vertical;
    }
</style>
