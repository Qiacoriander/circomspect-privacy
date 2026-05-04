# 隐私泄露审计报告：CGuthmann_Infrachain_ZeroKnowledge (MPC Claim)

## 1. 项目与漏洞概述
- **项目名**: `CGuthmann_Infrachain_ZeroKnowledge`
- **泄露类型**: **1 Full Leak (完全侧漏)**
- **涉及信号**: `totalSum` (全网能耗总量)
- **安全幸存信号**: `private_consumption` (个人能耗) **未泄漏** ✅

---

## 2. 漏洞发生链路分析

### 审计目标电路：`CGuthmann_Infrachain_ZeroKnowledge\circuits\circuit_claim.circom`

这是此前审计过的 RSA 加密项目同一团队的另一个电路——一个 **ZK-MPC 能耗声明**电路。功能是：证明某用户的 `private_consumption` 低于全网平均能耗的 3 倍。

```circom
template ZKP_MPC_Claim() {
    signal input totalSum;             // 全网能耗总量
    signal input private_consumption;  // 个人能耗（Private）

    // 对个人能耗做 Poseidon 哈希进行承诺
    comPrivateConsumption <== hasherPrivateConsumption.out;  // ✅ 安全

    // 检查 private_consumption < 3 * totalSum
    belowAverageCheck.in[0] <== private_consumption;
    belowAverageCheck.in[1] <== 3 * totalSum;
    belowAverageCheck.out === 1;

    // 重大失误：把 totalSum 直通输出
    totalSumOut <== totalSum;  // ❌
}
```

`totalSum` 的值通过 `totalSumOut <== totalSum` 直接泄漏。有趣的是，`private_consumption` 经过 Poseidon 哈希后作为承诺输出，引擎**没有对其发出任何告警**。

引擎还额外发现了 `LessThan` 比较器的输入缺乏非负约束（可能导致域溢出攻击），这是一个附加的安全发现。

## 3. 审计结论：确认为有效泄露 (True Positive)
与同项目的 RSA 电路类似——公共参数遗漏了 `{public}` 声明。`totalSum` 在 MPC 场景中确实需要公开（因为验证者需要知道平均值），但引擎的判定在语法层面完全正确。**True Positive**。
