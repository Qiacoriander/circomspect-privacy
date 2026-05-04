# 隐私泄露审计报告：santacroce-tech_zkgame (ZK 游戏：移动 + 时间制作)

## 1. 项目与漏洞概述
- **项目名**: `santacroce-tech_zkgame`（链上零知识游戏——含街道/城市/国家的探索型游戏世界）
- **涉及电路**:
  - `movement.circom`: **1 Full Leak** (`timestamp`)
  - `timeCraft.circom`: **1 Full Leak** (`newStateCommitment`)
- **安全幸存信号**: `playerId`, `inventory[64]`, `currency`, `ownedStores[10]` 等**均未泄漏** ✅

---

## 2. 漏洞发生链路分析

### 2.1 movement.circom — 玩家移动证明 (134行)

这是一个设计雄心勃勃的 ZK 游戏移动电路——包含了玩家 ID、区域类型（街道/城市/国家）、64 格背包、10 家商店、1000 个已探索区域、货币、声望、经验值等完整 RPG 元素。所有游戏状态通过 `PoseidonHash(12)` 压缩为状态承诺。

```circom
    signal input timestamp;        // 注释标为 "Public inputs"
    signal output timestampOut;
    timestampOut <== timestamp;    // ← 直通
```

`timestamp` 在注释中已标注为 "Public inputs"，但遗漏了 `{public}` 声明。核心的玩家状态全部经 Poseidon 哈希保护，引擎**未对任何游戏数据发出告警**。

### 2.2 timeCraft.circom — 时间制作证明

类似的模式——`newStateCommitment` 被直通输出。8 种制作材料、VDF 输出、制作配方等大量信号被声明但未使用（引擎额外报告了 7 个 unused signal 警告，说明电路处于开发初期）。

## 3. 审计结论：确认为有效泄露 (True Positive)
两个电路都是"注释写了 Public 但代码没声明"的典型白名单遗漏。值得注意的是，134 行代码中包含了大量 RPG 游戏状态（背包、商店、声望、经验值），引擎在如此复杂的上下文中**仅精准锁定了 `timestamp` 一个泄漏点**，没有任何误报。**True Positive**。
