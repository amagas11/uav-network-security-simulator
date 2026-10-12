<script setup lang="ts">
import { computed } from 'vue'
import { useSimulationStore } from '@/stores/simulation'
import NoticeBanner from './NoticeBanner.vue'

const props = defineProps<{ family: string; pageLabel: string }>()
const store = useSimulationStore()
const mismatched = computed(() => Boolean(store.runMetadata) && !store.isRunFor(props.family))
const activeLabel = computed(() => store.activeRunLabel || '基础通信')
</script>

<template>
  <NoticeBanner v-if="mismatched" title="当前运行与本页场景不同" tone="info">
    当前活动运行：{{ activeLabel }}；本页不显示或控制其他场景。
  </NoticeBanner>
</template>
