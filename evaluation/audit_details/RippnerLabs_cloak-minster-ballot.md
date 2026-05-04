# 隐私泄露审计报告：RippnerLabs_cloak-minster-ballot (匿名投票)

## 1. 项目与漏洞概述
- **项目名**: `RippnerLabs_cloak-minster-ballot`（"斗篷"匿名投票系统）
- **泄露类型**: **1 Full Leak (完全侧漏)**
- **涉及信号**: `spent_root` (已花费树 Merkle 根)
- **安全幸存信号**: `identity_nullifier`, `membership_merke_tree_siblings`, `spent_siblings` 等 **均未泄漏** ✅

---

## 2. 漏洞发生链路分析

### 审计目标电路：`RippnerLabs_cloak-minster-ballot\circom\vote\vote.circom`

这是一个**较为复杂的匿名投票协议**（90行），使用了双棵树设计：
- **成员树 (Membership Tree)**：证明投票者在注册选民名单中
- **花费树 (Spent Tree)**：用稀疏 Merkle 树追踪已投票的 nullifier，防止双重投票

整体架构设计很有想法，但：
```circom
    signal input spent_root;  // 当前花费树根（理应为 Public）

    // ... 大量 Poseidon 哈希和 Merkle 验证 ...

    spent_tree.curr_root <== spent_root;  // 用于非成员证明
```
`spent_root` 是链上公开的花费树状态根（用于验证某个 nullifier 还未被使用），但遗漏了 public 声明。由于 `curr_root === curr`（一个由内部计算得出的等式约束），`spent_root` 的值通过约束关系等价暴露。

## 3. 审计结论：确认为有效泄露 (True Positive)
与 `HoYongJin_zk-vote` 类似——一个精心设计的投票系统中，仅因为公共状态根遗漏了白名单声明而被引擎捕获。所有真正的隐私数据（身份 nullifier、Merkle 路径）均安全。**True Positive**。
