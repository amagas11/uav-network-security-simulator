# 三种检测模式与后台配置

## 模式对应关系

创建新实验时增加 `detection_mode`，不需要前端页面即可使用：

| 值 | 中文 | 业务协议可读 | 射频模块 | 射频防御 |
| --- | --- | --- | --- | --- |
| `APPLICATION_ONLY` | 仅原有上层检测 | 是 | 关闭 | 关闭 |
| `PHYSICAL_ONLY` | 仅物理身份检测 | 否 | 开启 | 执行 |
| `COMBINED` | 两层联合检测 | 是 | 开启 | 执行 |

这里的“上层检测”指项目原有整条检测流程，其中保留既有 DoS 信道规则，不是说原流程完全不读取 PHY 数据。物理模式的新模块针对本跳射频身份，不能替代射频抗干扰。

模式是三个底层开关的统一预设，优先于同一次请求中的 `application_layer_available`、`rff_enabled`、`rff_policy_mode`。其他阈值和 `flooding_detection_enabled` 等专项选项仍按各自配置；模式不会偷偷改动它们。不指定模式或设为 null 时保持旧行为，包括默认 RFF 仅观察。手动配置不属于三种组合时，输出模式为 `CUSTOM`。

通过原有 `POST /api/runs` 创建，例如：

```json
{"detection_mode": "PHYSICAL_ONLY", "duration_s": 6, "auto_advance": false}
```

Python 对应写法：

```python
from swarm_sim import PlatformRuntime, RunConfig

runtime = PlatformRuntime(RunConfig(detection_mode="COMBINED", duration_s=6))
runtime.run_to_completion()
print(runtime.run_record()["detection_configuration"])
runtime.close()
```

三份最小配置保存在 `config/detection_modes/`，可传给现有批量实验工具的 `--run-config`。模式在创建实验时确定，不在已运行实验中途切换；切换请重新创建实验，重置则保留当前模式。

## 输入与输出边界

PHYSICAL_ONLY 不解析业务载荷，不做业务 HMAC、序列号检查或业务执行。合法业务帧可以透明转发，到达目的端计入 `opaque_delivered_count`，不算业务执行成功。我们掌握的安全上报和密钥协商管理协议仍然需要认证，以便报告真正沿编队链路送达中心。

运行记录和 `/api/evaluation` 的 `detection_configuration` 提供实际配置：`mode` 为有效模式，`requested_mode` 为请求预设；`application_hmac.enabled`、`replay_protection.enabled`、`flooding.enabled` 标明业务侧是否参与；`management_authentication.enabled` 表示平台管理协议仍认证；`rff.enabled/enforcing/policy_mode` 表示射频模块是否观测及实际防御。

`run_config` 同时保留预设名称和解析后的底层开关；语义校验值只按有效开关计算，因此同样开关组合的预设和手动配置具有相同语义校验值。历史数据无需补填 `detection_mode`。

第一步验证：配置、接口、重置、历史数据及原有检测开关共 84 项测试通过。固定用例的三模式对比流程在下一步加入。
