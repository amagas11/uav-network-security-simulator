# 当前交付候选版本：V21_FINAL

这是V21基础上的最终显示与交付收口版本，不是新攻击机制版本。只读输入为无人机网络攻防仿真平台_V21.zip；不覆盖原V21。

四份交付：无人机网络攻防仿真平台_V21_FINAL.zip、V21_FINAL_VERIFICATION.zip、START_V21_FINAL.md、V21_FINAL_SHA256.json。正式源码清单SOURCE_MANIFEST_V21_FINAL.json，实际端口8114/4185。

本轮仅修复DoS认证失败报告数字段、布尔及缺失值显示，删除Overview运行趋势提示和全站Footer。认证失败累计取完整当前Run GCS inbox，不从600-event保留窗口计算。

evaluation.py仅为DoS追加实际政策损害输入与可用性元数据；原公式、阈值、原字段和双评价不改。缺少该输入时，前端不将历史默认true当作影响受控或防御成功。主工程496项、Person-A37项及前端closure/type-check/build、compileall本轮通过。

12组真实场景与六页三分辨率证据、25项答复、原始JSON和完整测试日志见验证包。源码及证据均须在交付前实际解压逐文件SHA校验；当前结果见交付SHA元数据。

保留短时DoS目标FPR正常样本不足、真实GCS次生告警等局限；不是外场或泛化性能证明。全新Windows依赖安装本轮未重新实施。停止追加功能，等待用户最终人工验收。
