# V21_FINAL 可移植集成布局

```text
无人机网络攻防仿真平台_V21_FINAL/
├── v8_platform/
│   ├── swarm_sim/
│   ├── app/
│   ├── Manager/
│   ├── tests/
│   └── UAV-project/UAV-project/
└── person_a_crypto/
    └── upstream/
        ├── crypto/
        ├── tests/
        └── docs/
```

Person-A 上游源码只保留一份，固定在 ASCII 稳定路径 `person_a_crypto/upstream/`。B 侧通过 `v8_platform/swarm_sim/integrations/person_a/` 的适配层接入，不复制或分叉 Person-A 密码实现。

ZIP 内部所有运行时依赖路径均为 ASCII；只有交付包顶层名称使用中文。标准 Python `zipfile.extractall()` 无需特殊 GBK 参数即可解压。
