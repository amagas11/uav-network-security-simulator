import { createRouter, createWebHistory } from 'vue-router'
const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    { path: '/', name: 'overview', component: () => import('@/views/OverviewView.vue'), meta: { title: '系统总览' } },
    { path: '/spoofing', name: 'spoofing', component: () => import('@/views/attacks/SpoofingView.vue'), meta: { title: '报文伪装' } },
    { path: '/fdi', name: 'fdi', component: () => import('@/views/attacks/FdiView.vue'), meta: { title: 'FDI攻击' } },
    { path: '/dos', name: 'dos', component: () => import('@/views/attacks/DosView.vue'), meta: { title: 'DoS攻击' } },
    { path: '/eavesdropping', name: 'eavesdropping', component: () => import('@/views/attacks/EavesdroppingView.vue'), meta: { title: '窃听攻击' } },
    { path: '/replay', name: 'replay', component: () => import('@/views/attacks/ReplayView.vue'), meta: { title: '重放攻击' } },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
  scrollBehavior: () => ({ top: 0 }),
})

router.afterEach((to) => {
  document.title = `${String(to.meta.title || '仿真平台')} · 无人机网络攻防仿真平台`
})

export default router
