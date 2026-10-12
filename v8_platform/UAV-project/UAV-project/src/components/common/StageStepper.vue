<script setup lang="ts">
defineProps<{ current: number; eavesdropping?: boolean }>()

const steps = ['攻击注入', '检测判定', '防御处置', '效果评估']
const eavesSteps = ['监听场景运行', '密钥协商', '密文业务发送', '保密结果评价']
</script>

<template>
  <div class="stepper" aria-label="攻击演示阶段">
    <template v-for="(step, index) in steps" :key="step">
      <div class="step" :class="{ active: current >= index + 1, current: current === index + 1 }">
        <b>{{ index + 1 }}</b>
        <span>{{ eavesdropping ? eavesSteps[index] : step }}</span>
      </div>
      <i v-if="index < steps.length - 1"></i>
    </template>
  </div>
</template>

<style scoped>
.stepper { display: grid; grid-template-columns: auto 1fr auto 1fr auto 1fr auto; align-items: center; padding: 15px 18px; border: 1px solid #dfe6ef; border-radius: 12px; background: white; box-shadow: 0 6px 20px rgba(20,46,79,.05); }
.step { display: flex; align-items: center; gap: 8px; color: #98a5b4; font-size: 12px; font-weight: 650; }
.step b { display: grid; place-items: center; width: 26px; height: 26px; border: 1px solid #cbd5e1; border-radius: 50%; background: white; }
.step.active { color: #25856b; }.step.active b { border-color: #28a17f; color: white; background: #28a17f; }.step.current { color: #246fe5; }.step.current b { border-color: #246fe5; background: #246fe5; box-shadow: 0 0 0 5px rgba(36,111,229,.12); }
.stepper > i { height: 2px; margin: 0 12px; background: #e1e7ef; }.step.active + i { background: #8eb9f3; }
@media (max-width: 760px) { .stepper { grid-template-columns: 1fr; gap: 9px; }.stepper > i { display: none; } }
</style>
