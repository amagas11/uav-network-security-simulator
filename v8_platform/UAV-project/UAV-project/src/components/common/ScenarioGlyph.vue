<script setup lang="ts">
import type { ScenarioKey } from '@/config/scenarios'

defineProps<{ scenario: ScenarioKey }>()
</script>

<template>
  <svg class="scenario-glyph" viewBox="0 0 24 24" aria-hidden="true">
    <g v-if="scenario === 'spoofing'">
      <path d="M4 5.5h10v13H4zM7 9h4M7 12h4M7 15h3" />
      <circle cx="17.5" cy="8" r="2.2" />
      <path d="M14.5 16c.4-2.6 1.4-4 3-4s2.6 1.4 3 4M16.3 8h2.4" />
    </g>
    <g v-else-if="scenario === 'fdi'">
      <path d="M3 13h4l2-7 4 13 2.5-9 2 3H21" />
      <circle cx="19" cy="6" r="2.2" />
      <path d="m18 6 1 1 2-3" />
    </g>
    <g v-else-if="scenario === 'dos'">
      <rect x="4" y="14" width="3" height="6" rx=".7" />
      <rect x="9" y="10" width="3" height="10" rx=".7" />
      <rect x="14" y="6" width="3" height="14" rx=".7" />
      <path d="M19 5v10m-2-2 2 2 2-2" />
    </g>
    <g v-else-if="scenario === 'eavesdropping'">
      <path d="M2.5 12s3.3-5 9.5-5 9.5 5 9.5 5-3.3 5-9.5 5-9.5-5-9.5-5Z" />
      <circle cx="12" cy="12" r="2.7" />
    </g>
    <g v-else>
      <path d="M4 12a8 8 0 1 0 2.3-5.7L4 8.7" />
      <path d="M4 4v4.7h4.7M12 8v4l3 2" />
    </g>
  </svg>
</template>

<style scoped>
.scenario-glyph { width: 23px; height: 23px; fill: none; stroke: currentColor; stroke-width: 1.7; stroke-linecap: round; stroke-linejoin: round; }
</style>
