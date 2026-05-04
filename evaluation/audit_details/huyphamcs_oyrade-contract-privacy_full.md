# 隐私泄露审计报告：huyphamcs_oyrade-contract-privacy (全系列：withdraw + deposit1 + combine1to2)

## 1. 项目与漏洞概述
- **项目名**: `huyphamcs_oyrade-contract-privacy` (Solnado — Solana 版 Tornado Cash)
- **涉及电路**: 3 个核心电路全部存在 Full Leak
  - `withdraw.circom`: 3 Full Leaks (`amount`, `noteNullifier`, `noteAssetId`)
  - `deposit1.circom`: 1 Full Leak (`amount`)
  - `combine1to2.circom`: 1 Full Leak (`inNullifier`)

---

## 2. 漏洞发生链路分析

### 2.1 withdraw.circom — 最严重

整个 Withdraw 电路的隐私保护设计可以说是"有名无实"：

```circom
template Withdraw(depth) {
    signal output amount32;    // PUBLIC
    signal output assetId;     // PUBLIC
    signal output nullifier;   // PUBLIC
    signal output root;        // PUBLIC

    signal input amount;       // PRIVATE
    signal input noteNullifier;// PRIVATE
    signal input noteAssetId;  // PRIVATE

    // Poseidon 计算 leaf...

    amount32 <== amount;           // ← 直通
    assetId <== noteAssetId;       // ← 直通
    nullifier <== noteNullifier;   // ← 直通
}
```

三个核心隐私字段（金额、nullifier、资产标识）都被**逐一等价赋值**给了公开输出。在 Tornado Cash 类协议中，这等于：
- 暴露了你转了多少钱（`amount`）
- 暴露了你的唯一身份废除符（`nullifier`）
- 暴露了你用的是什么币（`assetId`）

### 2.2 deposit1.circom

```circom
    leaf1 <== poseidon3.out;   // leaf 经 Poseidon 保护 ✅
    amount32 <== amount;       // 金额直通 ❌
```

存款电路中，叶子节点正确地被哈希保护了，但 `amount` 仍然被直通赋值给公开输出。

### 2.3 combine1to2.circom

```circom
    leaf1 <== hOut1.out;       // 输出叶子经 Poseidon 保护 ✅
    leaf2 <== hOut2.out;       // 输出叶子经 Poseidon 保护 ✅
    n1 <== inNullifier;        // nullifier 直通 ❌
```

组合拆分电路中，输出叶子正确使用了哈希保护，但 `inNullifier` 被直接暴露。

## 3. 审计结论：确认为有效泄露 (True Positive)

这是一个**系统性的隐私失败案例**——整个 Solnado 协议的全部 4 个核心电路（加上此前审计的 `merge2to2`）均存在 Full Leak。该开发者一致地把本应由 `{public [...]}` 白名单声明的信号留在了隐私域中，却又将它们的明文值赋给了公开输出。

更值得关注的是，Poseidon 哈希在这些电路中都被**正确使用**了（叶子计算是安全的），说明开发者理解密码学原语的用法，但对 Circom 的 public/private 声明语义存在根本性的误解。**True Positive**。
