<script setup lang="ts">
import { computed, onBeforeUnmount, ref } from "vue";
import {
  createRun,
  getEvaluation,
  getRunStatus,
  getRuntime,
  pauseRun,
  resetRun,
  resumeRun,
  scheduleAttack,
  startRun,
  stopRun,
  type OnlineEvent,
  type EvaluationView,
  type RuntimeMetrics,
  type RunStatus,
} from "@/api";

const seed = ref(42);
const nodeCount = ref(6);
const duration = ref(30);
const status = ref<RunStatus | null>(null);
const events = ref<OnlineEvent[]>([]);
const reports = ref<Array<Record<string, unknown>>>([]);
const metrics = ref<RuntimeMetrics>({});
const models = ref<Record<string, Record<string, unknown>>>({});
const evaluation = ref<EvaluationView | null>(null);
const runMetadata = ref<Record<string, unknown> | null>(null);
const cursor = ref(0);
const error = ref("");
const busy = ref(false);
const attackFamily = ref("SPOOFING");
const attackSubtype = ref("KNOWN_ID_CONFLICT");
let timer: ReturnType<typeof setInterval> | null = null;

const subtypes: Record<string, string[]> = {
  SPOOFING: ["UNKNOWN_ID", "KNOWN_ID_CONFLICT"],
  EAVESDROPPING: ["PASSIVE_CAPTURE"],
  DOS: ["FLOODING"],
  FDI: ["COMMAND_REPLACEMENT", "TELEMETRY_ABRUPT_CHANGE", "TELEMETRY_GRADUAL_DRIFT", "OUT_OF_RANGE_VALUE", "LOGICAL_INCONSISTENCY"],
  REPLAY: ["IMMEDIATE_REPLAY", "DELAYED_REPLAY", "OLD_SESSION_REPLAY"],
};

const progress = computed(() => {
  if (!status.value) return 0;
  return Math.min(100, (status.value.sim_time_s / status.value.duration_s) * 100);
});

function selectFamily(value: string) {
  attackFamily.value = value;
  attackSubtype.value = subtypes[value]?.[0] ?? "";
}

async function perform(action: () => Promise<unknown>) {
  busy.value = true;
  error.value = "";
  try {
    await action();
    await poll();
  } catch (value) {
    error.value = value instanceof Error ? value.message : String(value);
  } finally {
    busy.value = false;
  }
}

async function initialize() {
  await perform(async () => {
    await createRun({
      seed: seed.value,
      node_count: nodeCount.value,
      duration_s: duration.value,
      step_s: 0.2,
      encrypt_sensitive: attackFamily.value === "EAVESDROPPING",
      auto_advance: true,
      wall_interval_s: 0.08,
    });
    cursor.value = 0;
    events.value = [];
    reports.value = [];
    evaluation.value = null;
    runMetadata.value = null;
  });
}

async function poll() {
  if (!status.value && cursor.value === 0) {
    try {
      status.value = await getRunStatus();
    } catch {
      return;
    }
  }
  const view = await getRuntime(cursor.value);
  status.value = view.status;
  cursor.value = view.next_cursor;
  events.value = [...events.value, ...view.events].slice(-120);
  reports.value = view.security_reports;
  metrics.value = view.metrics;
  // Legacy component is no longer mounted by the formal application shell.
  // Keep the old diagnostics type-safe without reconnecting C-model status.
  models.value = {};
  runMetadata.value = view.run_metadata;
  if (view.status.state === "COMPLETED" && !evaluation.value) {
    evaluation.value = await getEvaluation();
  }
}

async function injectAttack() {
  if (!status.value) return;
  const impact = Math.min(status.value.sim_time_s + 0.4, status.value.duration_s - 0.2);
  if (impact <= status.value.sim_time_s) {
    error.value = "运行已接近结束，请重置后再注入攻击。";
    return;
  }
  const family = attackFamily.value;
  const compromisedNode = nodeCount.value > 2 ? 2 : 1;
  const targetNodeIds = family === "FDI" ? [1] : family === "EAVESDROPPING" ? [] : [1];
  await perform(() => scheduleAttack({
    attack_family: family,
    attack_subtype: attackSubtype.value,
    scheduled_start_s: status.value!.sim_time_s,
    impact_start_s: impact,
    end_s: Math.min(status.value!.duration_s, impact + 5),
    attacker_node_id: family === "FDI" ? compromisedNode : -1,
    target_node_ids: targetNodeIds,
    target_link_ids: [],
    intensity: family === "DOS" ? { value: 80, unit: "pps" } : {},
    parameters: family === "FDI"
      ? attackSubtype.value === "COMMAND_REPLACEMENT"
        ? { replacement: { cmd: "LAND", altitude_m: 0 } }
        : attackSubtype.value === "TELEMETRY_ABRUPT_CHANGE"
          ? { field: "altitude_m", absolute_offset: 50 }
          : attackSubtype.value === "TELEMETRY_GRADUAL_DRIFT"
            ? { field: "altitude_m", delta_per_step: 5 }
            : attackSubtype.value === "OUT_OF_RANGE_VALUE"
              ? { field: "altitude_m", value: 5000 }
              : { altitude_m: 120 }
      : family === "REPLAY" && attackSubtype.value === "DELAYED_REPLAY"
        ? { delay_s: 1.0 }
        : {},
  }));
}

timer = setInterval(() => void poll(), 700);
onBeforeUnmount(() => timer && clearInterval(timer));
</script>

<template>
  <main class="shell">
    <header class="hero">
      <div>
        <p class="eyebrow">DETERMINISTIC · {{ status?.software_version || "PLATFORM V7" }} · SCHEMA {{ status?.schema_version || "3.2.0" }}</p>
        <h1>无人机网络攻防仿真平台</h1>
        <p>节点本地观测、链路级传输与离线真值评估严格分离</p>
      </div>
      <div class="state" :data-state="status?.state || 'OFFLINE'">
        <span></span>{{ status?.state || "未初始化" }}
      </div>
    </header>

    <section class="toolbar card">
      <label>随机种子<input v-model.number="seed" type="number" /></label>
      <label>节点数<input v-model.number="nodeCount" type="number" min="3" max="30" /></label>
      <label>时长 / s<input v-model.number="duration" type="number" min="2" /></label>
      <button class="primary" :disabled="busy" @click="initialize">新建运行</button>
      <button :disabled="!status || busy" @click="perform(startRun)">启动</button>
      <button :disabled="status?.state !== 'RUNNING' || busy" @click="perform(pauseRun)">暂停</button>
      <button :disabled="status?.state !== 'PAUSED' || busy" @click="perform(resumeRun)">恢复</button>
      <button :disabled="!status || busy" @click="perform(stopRun)">停止</button>
      <button :disabled="!status || busy" @click="perform(resetRun)">重置</button>
    </section>

    <p v-if="error" class="error">{{ error }}</p>
    <div class="progress"><i :style="{ width: `${progress}%` }"></i></div>

    <section class="kpis">
      <article class="card"><small>仿真时间</small><strong>{{ status?.sim_time_s?.toFixed(1) || "0.0" }} s</strong></article>
      <article class="card"><small>GCS 可见事件</small><strong>{{ cursor }}</strong></article>
      <article class="card"><small>安全报告</small><strong>{{ reports.length }}</strong></article>
      <article class="card"><small>待调度攻击</small><strong>{{ status?.pending_attacks || 0 }}</strong></article>
      <article class="card"><small>数据成熟度</small><strong>{{ status?.dataset_maturity || "DEVELOPMENT" }}</strong></article>
    </section>

    <section class="grid">
      <article class="card attack-panel">
        <div class="section-title"><span>攻击计划</span><em>写操作</em></div>
        <div class="attack-tabs">
          <button v-for="family in Object.keys(subtypes)" :key="family" :class="{ active: attackFamily === family }" @click="selectFamily(family)">{{ family }}</button>
        </div>
        <label>攻击子型<select v-model="attackSubtype"><option v-for="item in subtypes[attackFamily]" :key="item">{{ item }}</option></select></label>
        <button class="danger" :disabled="!status || busy" @click="injectAttack">调度攻击</button>
        <p class="hint">Spoofing 仅改设备 ID；FLOODING 按接收端总速率检测；FDI 在 HMAC 后改业务字段；Replay 先验 HMAC 再查时间戳/会话/滑窗；窃听使用 CSI/SKG + AES-GCM。</p>
        <p class="hint">当前演示加密：{{ attackFamily === "EAVESDROPPING" ? "AES-GCM 开启" : "AES 关闭，应用 HMAC 开启" }}</p>
        <div class="section-title"><span>模型适配器</span><em>显式健康状态</em></div>
        <div v-for="(model, name) in models" :key="name" class="model-row">
          <b>{{ name }}</b><span>{{ model.status }}</span><code>{{ model.error_code || "—" }}</code>
        </div>
      </article>

      <article class="card stream-panel">
        <div class="section-title"><span>运行态势</span><em>仅 GCS 已接收数据</em></div>
        <div class="metric-row">
          <span>送达率 <b>{{ Number(metrics.delivery_rate || 0).toFixed(2) }}</b></span>
          <span>丢包率 <b>{{ Number(metrics.packet_loss_rate || 0).toFixed(2) }}</b></span>
          <span>迟到/缺失报告 <b>{{ metrics.missing_or_delayed_reports || 0 }}</b></span>
        </div>
        <div class="event-list">
          <div v-for="event in [...events].reverse()" :key="event.event_id" class="event-row">
            <time>{{ event.sim_time_s.toFixed(1) }}</time>
            <span :data-type="event.event_type">{{ event.event_type }}</span>
            <p>节点 {{ event.observer_node_id }} · {{ event.observer_role }}</p>
            <code>{{ event.online_features?.security_state?.application_hmac_result || event.message_id?.split('-msg-').pop() || '—' }}</code>
          </div>
          <p v-if="!events.length" class="empty">新建并启动运行后，这里显示 GCS 本地事件。</p>
        </div>
      </article>

      <article class="card eval-panel">
        <div class="section-title"><span>离线评估</span><em>真值隔离</em></div>
        <p v-if="status?.state !== 'COMPLETED'" class="empty">运行结束后才载入 labels.jsonl 语义的真值评估，在线检测器看不到此区域。</p>
        <template v-else-if="evaluation">
          <div class="scope">{{ evaluation.scope }}</div>
          <pre>{{ JSON.stringify(evaluation, null, 2) }}</pre>
        </template>
        <p v-else class="empty">正在生成评估结果…</p>
        <div class="section-title"><span>运行溯源</span><em>配置与计划指纹</em></div>
        <pre v-if="runMetadata">{{ JSON.stringify(runMetadata, null, 2) }}</pre>
        <p v-else class="empty">新建运行后显示完整无秘密 RunConfig、攻击/正常扰动计划和校准来源。</p>
      </article>
    </section>
  </main>
</template>

<style scoped>
:global(*) { box-sizing: border-box; }
:global(body) { margin: 0; min-width: 1080px; background: #060b16; color: #dfe8f5; font-family: Inter, "Microsoft YaHei", sans-serif; }
.shell { min-height: 100vh; padding: 26px 30px 40px; background: radial-gradient(circle at 50% -20%, #15355a 0, #081321 34%, #060b16 68%); }
.hero { display: flex; justify-content: space-between; align-items: center; max-width: 1600px; margin: auto auto 20px; }
.hero h1 { margin: 2px 0 7px; font-size: 30px; letter-spacing: .04em; }
.hero p { margin: 0; color: #8193aa; }
.eyebrow { color: #35d4c0 !important; font-size: 11px; font-weight: 800; letter-spacing: .22em; }
.state { display: flex; gap: 9px; align-items: center; padding: 10px 15px; border: 1px solid #24425e; border-radius: 999px; color: #9db0c5; }
.state span { width: 8px; height: 8px; border-radius: 50%; background: #718096; }
.state[data-state="RUNNING"] span { background: #2ee6b8; box-shadow: 0 0 14px #2ee6b8; }
.card { background: rgba(10, 24, 40, .91); border: 1px solid #1b3853; border-radius: 12px; box-shadow: 0 14px 35px rgba(0, 0, 0, .2); }
.toolbar { max-width: 1600px; margin: auto; display: flex; gap: 10px; align-items: end; padding: 14px; }
label { display: grid; gap: 6px; color: #8ea3ba; font-size: 12px; }
input, select { min-width: 105px; height: 36px; padding: 0 10px; border: 1px solid #284861; border-radius: 7px; background: #071521; color: #e8f0f8; }
button { height: 36px; padding: 0 15px; border: 1px solid #2a4962; border-radius: 7px; background: #10263a; color: #cddbea; cursor: pointer; }
button:hover:not(:disabled) { border-color: #36cdbb; color: white; }
button:disabled { opacity: .4; cursor: not-allowed; }
.primary { background: #0e8b83; border-color: #20bbae; color: white; }
.danger { width: 100%; margin: 14px 0; background: #8d3342; border-color: #d35a6d; }
.error { max-width: 1600px; margin: 10px auto; padding: 10px 14px; color: #ff9aa9; background: #401927; border-radius: 7px; }
.progress { max-width: 1600px; height: 3px; margin: 16px auto; overflow: hidden; background: #142b3e; }
.progress i { display: block; height: 100%; background: linear-gradient(90deg, #25d5bd, #54a8ff); transition: width .3s; }
.kpis { max-width: 1600px; margin: auto auto 16px; display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
.kpis article { padding: 15px 18px; }
.kpis small { display: block; margin-bottom: 7px; color: #718aa2; }
.kpis strong { font-size: 23px; color: #f4f8fb; }
.grid { max-width: 1600px; margin: auto; display: grid; grid-template-columns: 1fr 1.65fr 1.1fr; gap: 14px; align-items: start; }
.grid > article { min-height: 540px; padding: 17px; }
.section-title { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; font-weight: 700; }
.section-title em { padding: 4px 7px; color: #51d6c3; background: #123631; border-radius: 4px; font-size: 10px; font-style: normal; }
.attack-tabs { display: grid; grid-template-columns: repeat(2, 1fr); gap: 7px; margin-bottom: 14px; }
.attack-tabs button { padding: 0 7px; font-size: 11px; }
.attack-tabs .active { color: #62e4d1; border-color: #25a99a; background: #113a39; }
.hint, .empty { color: #71879e; font-size: 12px; line-height: 1.7; }
.model-row { display: grid; grid-template-columns: 1fr auto; gap: 3px 10px; padding: 10px 0; border-bottom: 1px solid #173047; font-size: 12px; }
.model-row span { color: #f3ba59; }
.model-row code { grid-column: 1 / -1; color: #6f879e; }
.metric-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin-bottom: 12px; }
.metric-row span { padding: 10px; background: #0a1a29; border-radius: 7px; color: #7791a8; font-size: 11px; }
.metric-row b { display: block; margin-top: 5px; color: #e8f3fb; font-size: 16px; }
.event-list { max-height: 450px; overflow: auto; }
.event-row { display: grid; grid-template-columns: 42px 108px 1fr auto; gap: 9px; align-items: center; padding: 9px 5px; border-bottom: 1px solid #142b3e; font-size: 11px; }
.event-row time, .event-row code { color: #69849c; }
.event-row p { margin: 0; color: #9eb0c1; }
.event-row span { color: #64dbc9; font-weight: 700; }
.event-row span[data-type="RX_FAILURE"] { color: #ff7185; }
.event-row span[data-type="DEFENSE_RESULT"] { color: #ffbd5c; }
.scope { padding: 8px; margin-bottom: 10px; color: #f3ba59; background: #302715; border-radius: 6px; font-size: 11px; }
pre { max-height: 445px; margin: 0; overflow: auto; color: #9bb5cb; font-size: 10px; line-height: 1.55; white-space: pre-wrap; }
@media (max-width: 1200px) { .grid { grid-template-columns: 1fr 1.5fr; } .eval-panel { grid-column: 1 / -1; } }
</style>
