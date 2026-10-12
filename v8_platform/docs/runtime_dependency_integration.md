# Runtime Dependency Integration

## Frozen API

`PlatformRuntime` 原有直接 provider/model 注入保持兼容。正式多入口使用：

```python
dependencies = RuntimeDependencies(
    key_provider_factory=...,
    crypto_provider_factory=...,
    model_adapter_factories={"bilstm": ..., "dueling_q": ..., "rff": ...},
    terminal_authorizer_factory=...,
    terminal_profiles_factory=...,
    terminal_credentials_factory=...,
    security_bundle_factory=...,  # optional coherent A-side bundle
)
factory = PlatformRuntimeFactory(dependencies)
runtime = factory.create(config, calibration_profile=profile)
```

每个 factory callback 每个 run/episode 调用一次；模型、key、crypto、terminal state 不跨 run 共享。crypto factory 获得与 runtime 相同的 fresh KeyProvider。

`security_bundle_factory(config)` 用于必须共享内部状态、但不得通过 B 暴露秘密的成套
安全实现。它返回同一 run 的 `key_provider`、`crypto_provider`、可选
`security_coordinator` 和 `terminal_authorizer`。Person-A 集成使用此入口，确保
node-local KeyProvider、SKG coordinator 与 AEAD adapter 指向同一批 fresh A 对象；
raw key 不进入 `RuntimeDependencies`。显式单项 factory 保持原有优先级和向后兼容。

## Entrypoint mapping

| Entrypoint | Injection |
|---|---|
| Direct | `PlatformRuntimeFactory.create` 或兼容的 `PlatformRuntime(...)` |
| SimulationManager/FastAPI | `SimulationManager(runtime_factory=...)`；正式 `app.app` 使用 `build_application_runtime_factory()` 注入 bundled Person-A；server startup 仍可 `configure_runtime_factory(...)` 替换 |
| Batch Python API | `run_batch(..., runtime_factory=...)` |
| RL | `UavDefenseEnv(..., runtime_factory=...)`；每次 reset fresh adapters |

HTTP/CLI 不接收任意 Python object。正式部署在 server/program startup 注册 A/C factory；run request 只传 strict serializable RunConfig 与 profile reference。

正式 Web composition root 以 `app/app.py` 的文件位置解析同级
`person_a_crypto/upstream`，而不是依赖 shell working directory。它创建 fresh
`PersonASecurityBundleFactory`，选择 `V8_DEFAULT` Probe 且不配置
`test_only_preloaded_keys`。裸 Direct/unit-test factory 的 mock/test 默认保持不变，防止
把轻量测试和正式应用依赖边界混在一起。

Manager reset 保留 RunConfig、CalibrationProfile 和 factory，但关闭旧 runtime 并创建新 run ID、empty event/queue/attack/model state。模型执行 supervisor 同样 per runtime；旧坏 run 的 timed-out worker 不占用新 runtime capacity。Python 无法安全强杀任意卡死 native/GPU 调用，正式 adapter 应尊重 deadline，此限制不改变跨 run isolation 语义。
