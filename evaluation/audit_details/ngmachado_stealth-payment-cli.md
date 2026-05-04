# 隐私泄露审计报告：ngmachado_stealth-payment-cli

## 1. 项目与漏洞概述
- **项目名**: `ngmachado_stealth-payment-cli`
- **泄露类型**: **1 Full Leak (完全侧漏)**
- **涉及信号**: `commitment` (隐匿支付的承诺值)
- **安全幸存信号**: `secret` (用户秘钥) **未泄漏** ✅

---

## 2. 漏洞发生链路分析

### 审计目标电路：`ngmachado_stealth-payment-cli\circuits\commitment.circom`

这是一个**隐匿支付（Stealth Payment）CLI 工具**的核心电路。其功能是：证明你知道某个 secret，它的 Poseidon 哈希等于已公开的 commitment，同时生成一个确定性 nullifier 防止双花。

```circom
template CommitmentProof() {
    signal input secret;        // Private
    signal input commitment;    // 注释写了 "Public Input"

    signal output computed_commitment;
    signal output computed_nullifier;

    // 用 Poseidon 从 secret 计算 commitment
    computed_commitment <== poseidon_commitment.out;

    // 验证提供的 commitment 和计算的匹配
    commitment === computed_commitment;

    // 从 commitment + secret 计算 nullifier
    computed_nullifier <== poseidon_nullifier.out;
}
component main = CommitmentProof(); // 没有 {public [commitment]}
```

问题出在作者注释中明确写了 `commitment` 是 "Public Input"，但在 `component main` 时遗漏了 `{public [commitment]}`。引擎将 `commitment` 判定为私有数据，而由于 `commitment === computed_commitment` 使 `commitment` 完全等价于 `computed_commitment`（一个暴露在公开 Output 上的值），构成 Full Leak。

关键亮点是 `secret` 由 Poseidon 单向保护，引擎**没有对其发出任何告警**。

## 3. 审计结论：确认为有效泄露 (True Positive)
和其他"遗漏白名单"案例类似，全因语法疏忽。在隐匿支付场景中，commitment 值本身就是链上公开信息，这更多是一个代码规范问题。但引擎的判定逻辑无可挑剔。**True Positive**。
