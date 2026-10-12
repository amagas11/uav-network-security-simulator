# SKG 所需无线观测（给 B）

本文从 [A1-观测与密码接口.md](A1-观测与密码接口.md) 第 2 节抽出，**只写密钥生成要你提供的无线观测**。加解密调用、包格式、失败码仍看 A1。

**版本：** 与 A1 草案 v0.1 对齐。改字段先改 A1 第 2 节，再同步本文。C 不需要这份。

---

## 1. 需求

密钥生成需要一次**邻接双端探测**：相邻两机在相近时刻各自测量自己收到的无线信道，并用同一次探测把两边的结果对上号。每端只使用本端测到的数据。信道对双方应接近互易，两端接收机噪声相互独立；不能把一端的测量复制加噪当作另一端。

现有业务通信里「这一包收得怎么样」那种单个功率/信噪比不能拿来生成密钥，那是单向、一包一个数。业务统计可以继续给前端；密钥另走探测。只对直接无线电邻居有效：中继或转发看到的是上一跳的发射，不能当成源节点的信道，也不存在「源到宿一整条信道」。

本阶段给一串接收功率即可；信道状态信息以后再加，暂时做不到就说明延后，不要编造。子载波、导频、天线、带宽、自动增益等细节本阶段不要求。探测如何从物理层采出，由你实现。

---

## 2. 每端交给 A 的对象：`LocalPhyObservation`

| 字段                 | 类型                     | 必填                   | 说明                                                                |
| ------------------ | ---------------------- | -------------------- | ----------------------------------------------------------------- |
| `local_id`         | int                    | 是                    | 本节点                                                               |
| `peer_id`          | int                    | 是                    | 对端（直接邻居）                                                          |
| `session_id`       | str                    | 是                    | 链路会话，例如 `link-3-7-s2`                                             |
| `probe_id`         | str                    | 是                    | **该字段用于配对，两端须相同，且不复用旧的id**                                        |
| `sim_time_s`       | float                  | 是                    | 仿真时刻，不用墙上时钟、不用业务包的 `timestamp`                                    |
| `freq_hz`          | float                  | 是                    | 探测载频；当前基线 `3.5e9`                                                 |
| `role`             | `"tx"` / `"rx"`        | 是                    | 本端在这次探测里是发还是收                                                     |
| `measurement_kind` | `"rssi_dbm"` 或 `"csi"` | 是                    | 标明本段 `measurement` 走哪路量化；本阶段用 `"rssi_dbm"`                        |
| `measurement`      | list                   | 是（`missing=false` 时） | 本端量测。RSSI：`list[float]`（dBm）。CSI：`list[[re, im]]`。长度两端应一致         |
| `snr_db`           | float 或 `null`         | 否                    | 本端对该次**探测**的信噪比估计；没有则 `null`。不要用业务包那个标量 SNR 冒充                    |
| `noise_var`        | float 或 `null`         | 否                    | 本端噪声方差；没有则 `null`                                                 |
| `missing`          | bool                   | 是                    | 本次本端观测**不能**给 SKG 用（超时、未收到、量测不可用）。`true` 时 A 返回 `skg_fail`，不要补默认数 |

`missing=false` 且 `measurement` 非空，A 才量化。

---

## 3. 样例

同一次探测（`probe_id` 均为 `prb-00042`），两端各一份。本阶段 RSSI 序列。

节点 3：

```json
{
  "local_id": 3,
  "peer_id": 7,
  "session_id": "link-3-7-s1",
  "probe_id": "prb-00042",
  "sim_time_s": 12.040,
  "freq_hz": 3500000000,
  "role": "rx",
  "measurement_kind": "rssi_dbm",
  "measurement": [-71.2, -70.8, -71.5, -70.9],
  "snr_db": 14.1,
  "noise_var": null,
  "missing": false
}
```

节点 7：

```json
{
  "local_id": 7,
  "peer_id": 3,
  "session_id": "link-3-7-s1",
  "probe_id": "prb-00042",
  "sim_time_s": 12.041,
  "freq_hz": 3500000000,
  "role": "tx",
  "measurement_kind": "rssi_dbm",
  "measurement": [-70.9, -71.1, -71.0, -71.4],
  "snr_db": 13.8,
  "noise_var": null,
  "missing": false
}
```

注意事项：

- 两边 `probe_id`、`session_id`、`freq_hz`、`measurement_kind` 相同；`local_id` / `peer_id` 相互对应。
- `measurement` 是各端自己测到的，长度一致、数值接近，但不要拷贝另一端的数组。
- `sim_time_s` 接近即可。
