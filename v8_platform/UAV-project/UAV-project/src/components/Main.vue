<script setup>
import { ref } from "vue";
import AttackControl from "./AttackControl.vue";
import Assessment from "./Assessment.vue";
import Map from "./Map.vue";

const latestTopologyEvent = ref(null);
const latestMetrics = ref({
  throughput: 0,
  packetLoss: 0,
  latency: 0,
  phase: "idle",
});
const latestRates = ref({
  attackSuccessRate: 0,
  detectionSuccessRate: 0,
  defenseSuccessRate: 0,
  phase: "idle",
});
const sessionInfo = ref({
  attackId: "",
  running: false,
});
/** POST /api/init 返回的节点坐标，用于拓扑图对齐后端 */
const topologyPayload = ref(null);
const defenseNodeSnapshot = ref(null);

const handleTopologyEvent = (event) => {
  latestTopologyEvent.value = { ...event, _ts: Date.now() };
};

const handleMetricsUpdate = (metrics) => {
  latestMetrics.value = metrics;
};

const handleEvaluationUpdate = (rates) => {
  latestRates.value = rates;
};

const handleSessionUpdate = (session) => {
  sessionInfo.value = session;
};

const handleTopologySync = (payload) => {
  topologyPayload.value = payload;
};

const handleDefenseNodeUpdate = (snapshot) => {
  defenseNodeSnapshot.value = snapshot;
};
</script>

<template>
    <div class="grid-container">
        <div class="layer">
            <AttackControl
              @topology-event="handleTopologyEvent"
              @topology-sync="handleTopologySync"
              @metrics-update="handleMetricsUpdate"
              @evaluation-update="handleEvaluationUpdate"
              @session-update="handleSessionUpdate"
              @defense-node-update="handleDefenseNodeUpdate"
            />
        </div>
        <div class="layer">
            <Map
              :latest-event="latestTopologyEvent"
              :session-info="sessionInfo"
              :topology-payload="topologyPayload"
              :defense-snapshot="defenseNodeSnapshot"
            />
        </div>
        <div class="layer">
            <Assessment
              :metrics-snapshot="latestMetrics"
              :rate-snapshot="latestRates"
              :session-info="sessionInfo"
            />
        </div>
    </div>
    
</template>

<style>
    .grid-container {
        display: grid;
        grid-template-columns: 2fr 4fr 3fr; 
        column-gap: 1em;
        margin: 0rem 1.5rem 1.5rem 1.5rem;
    }
    .layer {
        background-color: #0F172B;
        border-radius: 10px;
    }
</style>