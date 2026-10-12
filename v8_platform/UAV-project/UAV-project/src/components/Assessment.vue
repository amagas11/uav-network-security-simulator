<script setup>
import { computed, ref, watch } from "vue";
import AssessmentIcon from "@/components/icons/AssessmentIcon.vue";
import RiseIcon from "@/components/icons/RiseIcon.vue";
import FallIcon from "@/components/icons/FallIcon.vue";
import LineChart from "@/components/charts/LineChart.vue";
import BarChart from "@/components/charts/BarChart.vue";

const props = defineProps({
  metricsSnapshot: {
    type: Object,
    default: () => ({ throughput: 0, packetLoss: 0, latency: 0, phase: "idle" }),
  },
  rateSnapshot: {
    type: Object,
    default: () => ({ attackSuccessRate: 0, detectionSuccessRate: 0, defenseSuccessRate: 0, phase: "idle" }),
  },
  sessionInfo: {
    type: Object,
    default: () => ({ running: false }),
  },
});

const throughputSeries = ref([]);
const lossSeries = ref([]);
const trendLabels = ref([]);

const phaseText = computed(() => {
  if (!props.sessionInfo?.running) return "当前阶段：待机";
  const phase = props.metricsSnapshot?.phase || "running";
  const map = {
    attack: "当前阶段：攻击进行中",
    detect: "当前阶段：检测进行中",
    defense: "当前阶段：防御进行中",
    recover: "当前阶段：恢复中",
  };
  return map[phase] || "当前阶段：执行中";
});

const metrics = computed(() => [
  {
    title: "吞吐量",
    value: Number(props.metricsSnapshot?.throughput || 0).toFixed(2),
    unit: "%",
    description: "网络容量利用率",
    goodThreshold: 60,
    reverse: false,
    icons: [RiseIcon, FallIcon],
  },
  {
    title: "丢包率",
    value: Number(props.metricsSnapshot?.packetLoss || 0).toFixed(2),
    unit: "%",
    description: "数据包丢失",
    goodThreshold: 20,
    reverse: true,
    icons: [FallIcon, RiseIcon],
  },
  {
    title: "延迟",
    value: Number(props.metricsSnapshot?.latency || 0).toFixed(2),
    unit: "ms",
    description: "网络延迟",
    goodThreshold: 50,
    reverse: true,
    icons: [FallIcon, RiseIcon],
  },
]);

const rateData = computed(() => [
  Math.round((props.rateSnapshot?.attackSuccessRate || 0) * 100),
  Math.round((props.rateSnapshot?.detectionSuccessRate || 0) * 100),
  Math.round((props.rateSnapshot?.defenseSuccessRate || 0) * 100),
]);

const isNormal = (item) => (item.reverse ? Number(item.value) <= item.goodThreshold : Number(item.value) >= item.goodThreshold);
const getColor = (item) => (isNormal(item) ? "#00D492" : "#E84344");

watch(
  () => props.metricsSnapshot,
  (snapshot) => {
    const now = new Date();
    const label = `${String(now.getMinutes()).padStart(2, "0")}:${String(now.getSeconds()).padStart(2, "0")}`;
    trendLabels.value.push(label);
    throughputSeries.value.push(Number(snapshot?.throughput || 0).toFixed(2));
    lossSeries.value.push(Number(snapshot?.packetLoss || 0).toFixed(2));

    if (trendLabels.value.length > 10) {
      trendLabels.value.shift();
      throughputSeries.value.shift();
      lossSeries.value.shift();
    }
  },
  { deep: true },
);

</script>

<template>
    <div class="flex-container">
        <!-- 标题区域 -->
        <div class="title">
            <AssessmentIcon/>
            <span>效果评估</span>
        </div>
        <div class="phase-text">{{ phaseText }}</div>

        <!-- 指标卡片 -->
        <div class="metric-cards">
            <div
                v-for="item in metrics"
                :key="item.title"
                class="card"
                >
                <div class="card-title">
                    {{ item.title }}
                    <component 
                        v-if="isNormal(item) === true" 
                        :is="item.icons[0]" 
                        class="card-icon"
                        :style="{ color: getColor(item) }"
                        >
                    </component>
                    <component 
                        v-else-if="isNormal(item) === false" 
                        :is="item.icons[1]" 
                        class="card-icon"
                        :style="{ color: getColor(item) }"
                        >
                    </component>
                </div>
                <div class="card-value"
                    :style="{ color: getColor(item) }">
                    {{ item.value }}{{ item.unit }}
                </div>
                <div class="card-description">
                    {{ item.description }}
                </div>
            </div>
        </div>

        <div class="card">
            <LineChart :labels="trendLabels" :throughput-data="throughputSeries" :loss-data="lossSeries" />
        </div>

        <div class="card">
            <BarChart :rate-data="rateData" />
        </div>

    </div>
</template>

<style scoped>
    .flex-container {
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

    .metric-cards {
        display: grid;
        grid-template-columns: 1fr 1fr 1fr;
        gap: 0.5rem;
    }

    .phase-text {
        color: #90A1B9;
        font-size: medium;
    }

    .card {
        background-color: #1D293D;
        border: solid #28364C;
        border-width: thin;
        border-radius: 10px;
        padding: 1rem;
    }

    .card-title {
        display: flex;
        flex-direction: row;
        align-items: center;
        justify-content: space-between;
        font-size: large;
        color: #90A1B9;
        margin-bottom: 0.5rem;
    }

    .card-icon {
        width: 1rem;
        height: 1rem;
    }

    .card-value {
        font-size: x-large;
    }

    .card-description {
        color: #90A1B9;
        font-size: medium;
        margin-top: 0.1rem;
    }

</style>