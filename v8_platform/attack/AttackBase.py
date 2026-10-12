
# ==========================================
# 第三部分：安全对抗模块接口 (Attack/Detect/Defense)
# ==========================================

class AttackBase:
    def __init__(self, name):
        self.name = name

    def execute(self, packet, context=None):
        """
        输入: 原始报文
        输出: (修改后的报文, 攻击元数据)
        """
        raise NotImplementedError