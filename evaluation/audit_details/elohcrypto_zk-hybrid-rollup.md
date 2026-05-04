# 隐私泄露审计报告：elohcrypto_zk-hybrid-rollup

## 1. 项目与漏洞概述
- **项目名**: `elohcrypto_zk-hybrid-rollup`
- **泄露类型**: **1 Full Leak (完全侧漏)**
- **涉及信号**: `batchId` (批次标识符)
- **安全幸存信号**: `amounts`, `senderLeaves`, `receiverLeaves`, `senderNullifiers` 等核心交易数据**均未泄漏**

---

## 2. 漏洞发生链路分析

### 审计目标电路：`elohcrypto_zk-hybrid-rollup\circuits\batch.circom`

这是一个混合 Rollup 的批处理电路，在同一个证明中验证多笔交易并生成聚合后的 Merkle Root。

#### Full Leak: batchId 的明文直排
```circom
    signal input batchId; // Batch identifier
    signal output publicBatchId; // Public batch identifier
    publicBatchId <== batchId; // Expose batchId as public signal
```
作者在注释里写了 "Expose batchId as public signal"，说明这个值**本意就是 public 的**，但由于 `component main = Batch(4, 2)` 没有声明 `{public [batchId]}`，引擎将其默认为私有输入。随后的直接赋值就构成了 Full Leak。

#### 引擎的精确防守：核心交易数据未被误报
更重要的是，电路中大量核心的交易隐私数据（`amounts`, `senderLeaves`, `senderNullifiers`, `receiverBalances` 等）全部经过了 Poseidon 哈希或 Merkle Tree 处理后才进入 output。引擎对这些信号**保持了沉默**——没有任何 False Positive（假阳性）的误报。

## 3. 审计结论：确认为有效泄露 (True Positive)
`batchId` 回归公共域本身可能属于开发者本意（因为批次号本身不携带交易机密），但引擎严格按照"是否落入 public 声明白名单"进行判定的逻辑是铁面无私且完全正确的。同时，引擎精确"放过了"所有经哈希脱敏的交易数据，体现了良好的区分精度。**True Positive**。
