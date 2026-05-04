# 隐私泄露审计报告：santacroce-tech_zkgame (时间奖励) + DebRC_Vortex (高Gas电路)

## 1. 概述

### santacroce-tech_zkgame — timeReward.circom  
- **泄露类型**: **1 Full Leak** (`newStateCommitment`)
- 与 movement.circom 和 timeCraft.circom 完全同一模式——`newStateCommitment` 作为链上预期的公共值，遗漏了 `{public}` 声明后被直通输出。
- 引擎额外发现 3 个 unused variable 警告（`MIN_CLAIM_INTERVAL`、`BASE_REWARD_RATE`、`MAX_CLAIM_INTERVAL`），证实电路处于开发初期。

### DebRC_Vortex — zk_circuit_1.circom
- **泄露类型**: **1 Full Leak** (`x`)
- 这是一个有趣的 **Gas 成本基准测试电路**（命名为 `HighGasCircuit`），通过生成 42 个公开输出来模拟高 Gas 消耗：
  ```circom
  for (var i = 0; i < n; i++){
      out[i] <== x + i;   // out[0]=x, out[1]=x+1, ..., out[41]=x+41
  }
  ```
  由于 `out[0] = x`，Full Leak 不言自明。注释标注 `// Gas Cost: 494K`。

## 2. 审计结论：均确认为有效泄露 (True Positive)
两者都是简单直接的泄漏模式。**True Positive**。
