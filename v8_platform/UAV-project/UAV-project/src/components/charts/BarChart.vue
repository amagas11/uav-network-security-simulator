<script setup>
import DefenseIcon from "@/components/icons/DefenseIcon.vue";
import { onMounted, onBeforeUnmount, ref, watch } from "vue";
import * as echarts from "echarts";

const props = defineProps({
  rateData: {
    type: Array,
    default: () => [0, 0, 0],
  },
});

const chartRef = ref(null);
let chart = null;

const render = () => {
  if (!chart) return;
  chart.setOption({
    grid: { left: "10%", right: "10%", bottom: "5%", top: "15%" },
    xAxis: {
      type: "category",
      data: ["攻击成功率", "检测成功率", "防御成功率"],
      axisLine: { lineStyle: { color: "#94A3B8" } },
      axisLabel: {
        color: "#94A3B8",
        fontSize: 15,
      },
    },
    yAxis: {
      type: "value",
      max: 100,
      axisLabel: { color: "#94A3B8" },
      axisTick: { show: true },
      axisLine: { show: true, lineStyle: { color: "#94A3B8" } },
      splitLine: { lineStyle: { type: "dashed", color: "#334155" } },
    },
    series: [
      {
        type: "bar",
        barWidth: 90,
        itemStyle: {
          borderRadius: [10, 10, 0, 0],
        },
        label: {
          show: true,
          position: "inside",
          formatter: "{c}%",
          fontSize: 20,
          color: "#fff",
        },
        data: [
          { value: props.rateData[0] || 0, itemStyle: { color: "#8884D8" } },
          { value: props.rateData[1] || 0, itemStyle: { color: "#FFC107" } },
          { value: props.rateData[2] || 0, itemStyle: { color: "#00E396" } },
        ],
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

watch(() => props.rateData, render, { deep: true });

onBeforeUnmount(() => {
  window.removeEventListener("resize", resize);
  if (chart) chart.dispose();
});
</script>

<template>
    <div class="chart-title">
        <DefenseIcon class="title-icon"/>
        攻防成功率
    </div>
    <div ref="chartRef" class="bar-chart"></div>
</template>

<style scoped>
    .chart-title {
        display: flex;
        flex-direction: row;
        color: #CAD5E2;
        align-items: center;
        gap: 0.5rem;
    }

    .title-icon {
        width: 1rem;
        height: 1rem;
    }

    .bar-chart {
        width: 100%;
        height: 25vh;
    }

</style>