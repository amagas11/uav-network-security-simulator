<script setup lang="ts">
import { computed } from 'vue'
import { useSimulationStore } from '@/stores/simulation'

const items = [
  { to: '/', label: '系统总览', icon: 'overview' },
  { to: '/spoofing', label: '报文伪装', icon: 'identity' },
  { to: '/fdi', label: 'FDI攻击', icon: 'fdi' },
  { to: '/dos', label: 'DoS攻击', icon: 'dos' },
  { to: '/eavesdropping', label: '窃听攻击', icon: 'eaves' },
  { to: '/replay', label: '重放攻击', icon: 'replay' },
]

const store = useSimulationStore()
const connectionLabel = computed(() => {
  if (store.runtimeConnectionState === 'CONNECTED') return 'Runtime 已连接'
  if (store.runtimeConnectionState === 'DISCONNECTED') return 'Runtime 连接异常'
  return '正在连接 Runtime'
})
const connectionNote = computed(() => {
  if (store.runtimeConnectionState === 'CONNECTED') return store.runAvailable ? '当前运行数据同步中' : '服务可达 · 尚无当前运行'
  if (store.runtimeConnectionState === 'DISCONNECTED') return '请检查 FastAPI 服务'
  return '等待首次状态检查'
})
</script>

<template>
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-mark"><svg viewBox="0 0 32 24" aria-hidden="true"><ellipse cx="6" cy="5" rx="5" ry="2"/><ellipse cx="26" cy="5" rx="5" ry="2"/><ellipse cx="6" cy="19" rx="5" ry="2"/><ellipse cx="26" cy="19" rx="5" ry="2"/><path d="m7 7 6 4m6 0 6-4M7 17l6-4m6 0 6 4"/><rect x="12" y="8" width="8" height="8" rx="3"/></svg></div>
      <div><strong>无人机网络攻防仿真平台</strong><span>UAV Network Security Simulation</span></div>
    </div>
    <p class="nav-title">演示场景</p>
    <nav>
      <RouterLink v-for="item in items" :key="item.to" :to="item.to" class="nav-link">
        <svg v-if="item.icon === 'overview'" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>
        <svg v-else-if="item.icon === 'identity'" viewBox="0 0 24 24"><circle cx="9" cy="8" r="3"/><path d="M3.5 19c.6-4 2.5-6 5.5-6s4.9 2 5.5 6M16 7h5M18.5 4.5v5"/></svg>
        <svg v-else-if="item.icon === 'fdi'" viewBox="0 0 24 24"><path d="M4 18V6m0 12h16M7 14l4-4 3 2 5-6"/><circle cx="19" cy="6" r="2"/></svg>
        <svg v-else-if="item.icon === 'dos'" viewBox="0 0 24 24"><path d="M4 7h16M4 12h16M4 17h10"/><path d="m17 15 4 4m0-4-4 4"/></svg>
        <svg v-else-if="item.icon === 'eaves'" viewBox="0 0 24 24"><path d="M2.5 12s3.3-5 9.5-5 9.5 5 9.5 5-3.3 5-9.5 5-9.5-5-9.5-5Z"/><circle cx="12" cy="12" r="2.7"/></svg>
        <svg v-else viewBox="0 0 24 24"><path d="M4 12a8 8 0 1 0 2.3-5.7L4 8.6"/><path d="M4 4v4.6h4.6M12 8v5l3 2"/></svg>
        <span>{{ item.label }}</span>
      </RouterLink>
    </nav>
    <div class="sidebar-foot" :class="`connection-${store.runtimeConnectionState.toLowerCase()}`">
      <i></i><div><strong>{{ connectionLabel }}</strong><span>{{ connectionNote }}</span></div>
    </div>
  </aside>
</template>

<style scoped>
.sidebar { position: fixed; inset: 0 auto 0 0; z-index: 20; width: 224px; padding: 20px 14px; color: #dbe7f5; background: linear-gradient(180deg, #0a2343 0%, #071a31 100%); box-shadow: 5px 0 22px rgba(12,35,64,.12); }
.brand { display: flex; align-items: center; gap: 11px; min-height: 70px; padding: 0 6px 18px; border-bottom: 1px solid rgba(255,255,255,.09); }
.brand-mark { display: grid; place-items: center; width: 38px; height: 38px; border-radius: 10px; background: linear-gradient(145deg,#2d7be7,#55a6ff); box-shadow: 0 8px 20px rgba(46,123,231,.32); }
.brand-mark svg { width: 24px; fill: none; stroke: white; stroke-width: 1.5; }
.brand strong, .brand span { display: block; }.brand strong { max-width: 154px; font-size: 14px; line-height: 1.42; letter-spacing: .01em; }.brand span { max-width: 154px; margin-top: 4px; color: #8eabc9; font-size: 10px; line-height: 1.35; }
.nav-title { margin: 22px 10px 10px; color: #6f8baa; font-size: 10px; font-weight: 700; letter-spacing: .16em; }
nav { display: grid; gap: 5px; }
.nav-link { display: flex; align-items: center; gap: 12px; min-height: 44px; padding: 0 13px; border-radius: 9px; color: #9eb3cb; font-size: 13px; font-weight: 600; transition: .18s ease; }
.nav-link svg { width: 19px; height: 19px; fill: none; stroke: currentColor; stroke-width: 1.6; }
.nav-link:hover { color: white; background: rgba(71,130,201,.16); }
.nav-link.router-link-exact-active { color: white; background: linear-gradient(90deg, rgba(53,126,221,.92), rgba(39,102,184,.88)); box-shadow: 0 7px 17px rgba(16,73,145,.25); }
.sidebar-foot { position: absolute; right: 18px; bottom: 20px; left: 18px; display: flex; align-items: flex-start; gap: 9px; padding: 12px; border: 1px solid rgba(255,255,255,.08); border-radius: 10px; background: rgba(255,255,255,.035); }
.sidebar-foot i { flex: 0 0 7px; width: 7px; height: 7px; margin-top: 3px; border-radius: 50%; background: #8796a8; box-shadow: 0 0 8px rgba(135,150,168,.55); }
.sidebar-foot.connection-connected i { background: #3bd89d; box-shadow: 0 0 10px #3bd89d; }
.sidebar-foot.connection-disconnected i { background: #f15b67; box-shadow: 0 0 10px rgba(241,91,103,.75); }
.sidebar-foot strong, .sidebar-foot span { display: block; }.sidebar-foot strong { font-size: 10px; }.sidebar-foot span { margin-top: 4px; color: #7591af; font-size: 9px; line-height: 1.4; }
@media (max-width: 900px) { .sidebar { width: 72px; padding: 18px 9px; }.brand { justify-content: center; padding: 0 0 15px; }.brand > div:last-child, .nav-title, .nav-link span, .sidebar-foot { display: none; }.nav-link { justify-content: center; padding: 0; }.nav-link svg { width: 22px; height: 22px; } }
</style>
