<script setup>
    import {ref} from 'vue'
    const title = ref('无人机网络安全攻防演示系统')
    const subtitle = ref('实时监控网络攻击、态势展示与防御效果评估')
    const btn_1 = ref('联系')
    const btn_2 = ref('其他')
</script>

<!-- <template>
  <div class="header">
    <span class="main_title">
        <img class="svg" src="../assets/imgs/无人机.svg"/>
        <h1>{{ title }}</h1> 
        <button>联系</button>
        <button>其他</button>
    </span>
    
  </div>
</template> -->

<!-- <style scoped>
    .header {
        padding: 20px;
    }
    .icon_text {
        display: flex;
        flex-direction: row;
        align-items: center;
    }
    .main_title {
        display: flex;
        flex-direction: row;
        align-items: center;
    }
    .main_title .svg {
        width: 50px;
    }
    .main_title h1 {
        color: #fff;
        flex-grow: 1;   /* 挤占剩余空间 */
    }
    .main_title button {
        color: #fff;
        background-color: #020618;
    }
    .subtitle {
        color: #90A1B9;
    }
    
</style> -->

<!--如何悬浮？-->
<template>
    <div class="grid_container">
        <span class="svg" aria-hidden="true">✦</span>
        <h1>{{ title }}</h1>
        <div class="buttons">
            <button>{{ btn_1 }}</button>
            <button>{{ btn_2 }}</button>
        </div>
        <p class="subtitle">{{ subtitle }}</p>
    </div>
    
</template>

<style scoped>
    .grid_container {
        display: grid;
        grid-template-columns: 1fr auto 1fr;
        column-gap: 1rem;
        margin-top: 1rem;
        align-items: center;
        justify-items: center;
    }
    .svg {
        width: 3em; 
        height: 3em;
        object-fit: contain;
        justify-self: end;
        margin-right: 0.5rem;
    }
    h1 {
        color: #fff;
        /* margin-bottom: 0; */
    }
    .subtitle {
        color: #90A1B9;
        grid-column: 2;
        margin-top: -1rem;
        font-size: large;
    }
    .buttons {
        display: flex;
        /* gap: 1rem; */
        justify-self: end; /* 按钮右对齐 */
    }
    .buttons button {
        font-size: 1rem;
        padding: 0.5rem 1rem;
        color: #fff;
        background-color: #020618;
        border: none;
    }
</style>
