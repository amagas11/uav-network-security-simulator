<script setup>
import { onMounted, onBeforeUnmount, ref, watch } from "vue";
import * as echarts from "echarts";

const props = defineProps({
  labels: {
    type: Array,
    default: () => [],
  },
  throughputData: {
    type: Array,
    default: () => [],
  },
  lossData: {
    type: Array,
    default: () => [],
  },
});

const chartRef = ref(null);
let chart = null;

const render = () => {
  if (!chart) return;
  chart.setOption({
    color: ["#10B981", "#E84344"],
    tooltip: { trigger: "axis" },
    legend: {
      data: ["吞吐量(%)", "丢包率(%)"],
      top: "top",
      textStyle: {
        rich: {
          a: { color: "#10B981" },
          b: { color: "#E84344" },
        },
      },
    },
    grid: { left: "10%", right: "10%", bottom: "5%", top: "15%", containLabel: true },
    xAxis: {
      type: "category",
      data: props.labels.length ? props.labels : ["--"],
      boundaryGap: false,
      axisLine: { lineStyle: { color: "#94A3B8" } },
      axisLabel: { color: "#94A3B8" },
    },
    yAxis: {
      type: "value",
      max: 100,
      splitNumber: 5,
      axisLine: { show: true, lineStyle: { color: "#94A3B8" } },
      axisLabel: { color: "#94A3B8" },
      axisTick: { show: true },
      splitLine: { lineStyle: { type: "dashed", color: "#334155" } },
    },
    series: [
      {
        name: "吞吐量(%)",
        type: "line",
        smooth: true,
        data: props.throughputData.length ? props.throughputData : [0],
      },
      {
        name: "丢包率(%)",
        type: "line",
        smooth: true,
        data: props.lossData.length ? props.lossData : [0],
      },
    ],
  });
};

onMounted(() => {
  chart = echarts.init(chartRef.value);
  render();
  window.addEventListener("resize", resize);
});

const resize = () => chart && chart.resize();

watch(() => [props.labels, props.throughputData, props.lossData], render, { deep: true });

onBeforeUnmount(() => {
  window.removeEventListener("resize", resize);
  if (chart) chart.dispose();
});
</script>

<template>
    <div class="chart-title">网络性能趋势</div>
    <div ref="chartRef" class="line-chart"></div>
</template>

<style scoped>
    .chart-title {
        color: #CAD5E2;
    }

    .line-chart {
        width: 100%;
        height: 20vh;
    }

</style>