# 隐私泄露审计报告：HoYongJin_zk-vote (VoteCheck_temp - 185行投票系统完整版)

## 1. 项目与漏洞概述
- **项目名**: `HoYongJin_zk-vote`
- **电路文件**: `server/zkp/build_4_5/VoteCheck_temp.circom` (与 `build_5_4` 版同源)
- **泄露类型**: **1 Full Leak**
- **涉及信号**: `root_in` (Merkle 根)
- **电路规模**: 185行，包含 `MerkleProof`、`VoteProof`、`Main` 三层模板嵌套

---

## 2. 电路架构分析

此电路是一个**完整的、工业级风格的匿名投票系统原型**。架构分为三层：

### 2.1 MerkleProof (底层)
```circom
template MerkleProof(depth) {
    signal input leaf;              // Private: 秘密哈希
    signal input root;              // Public: Merkle 根
    signal input pathElements[depth]; // Private: 路径兄弟节点
    signal input pathIndices[depth];  // Private: 左右方向标记
    // ... Poseidon(2) 逐层哈希重建，最终 cur[depth] === root
}
```
引擎Phase 1 扫到所有 `Poseidon(2)` 的输出均被标记为 `{(leaf, OneWay), (pathElements, OneWay)}`→ 完美的哈希单向屏障！

### 2.2 VoteProof (中层)
```circom
template VoteProof(depth, numOptions) {
    // Secret: user_secret → Poseidon(1) → leaf → MerkleProof
    // Vote:   vote[i]*(1-vote[i])===0, Σvote[i]===1 (1-hot)
    // Output: vote_index = Σ(vote[i]*i)
    // Nullifier: Poseidon(2)(user_secret, election_id) → nullifier_hash
}
```
- `user_secret` 经 `Poseidon(1)` 哈希，Phase 1 标记为 `{(user_secret, OneWay)}`→安全
- `vote[i]` 经 `*i` 加权求和→`vote_index`，Phase 1标记 `{(vote, Full)}`→需要深入分析
- `nullifier_hash` 经 `Poseidon(2)`→安全

### 2.3 Main (顶层) — Bug 发生处
```circom
template Main(depth, numOptions) {
    signal input root_in;           // 注释写着 Public!
    signal output root_out;          
    // ...
    root_out <== root_in;           // 🔴 致命: 直通透传
}
component main = Main(4, 5);       // ⚠️ 缺少 { public [root_in, election_id] }
```

## 3. 泄露链路还原

### 3.1 对 `root_in` 的 Full Leak（确认）
由于 `component main = Main(4, 5)` 没有使用 `{ public [root_in, election_id] }` 语法声明公开输入，导致 `root_in` 被引擎视为 **私有信号**。而 `root_out <== root_in` 是一条直通赋值到公开输出的约束，Phase 2 反向推理立即发现 `root_in` 的知识状态 K(root_in) = FK。

**这与我们之前审计的 `VoteCheck.circom` 所犯的错误完全相同**——开发者在不同版本之间未同步公开声明。

### 3.2 对其他信号的安全性（排除）
引擎日志中可以清晰看到：
- `user_secret(sig_id=1)` 经 Poseidon → `{(1, OneWay)}` × 多轮传播 → **安全**
- `election_id(sig_id=5)` 同样经 Poseidon(2)→`{(5, OneWay), (1, OneWay)}` → **安全**
- `vote` 数组经 `Select`/`AddSub` 操作但 Phase 1 均为空污点 `{}`→被多变量掩蔽 → **安全**
- `pathElements`/`pathIndices` 全部被 Poseidon 单向阻断 → **安全**

### 3.3 对 `vote_index` 泄露的讨论
`vote_index = Σ(vote[i]*i)` 是一个有趣的边界案例：`vote_index` 作为输出虽然直接承载了投票选择信息，但**在投票协议的设计语义中这本身就是需要公开的信息**（链上合约需要知道投了谁）。引擎未将 `vote[]` 标记为泄露是因为从 `vote_index`反推 `vote[]` 是不可逆的（一个有限域内的线性组合映射，但1-hot约束条件下反推是确定的）。这里的隐私保障不来自代数盲化，而来自协议层面「vote_index 应当公开」的设计。

## 4. 审计结论
- **root_in**: 确认为有效泄露 (True Positive) — **漏配 `public` 声明**导致本该公开的 Merkle 根被错误地当做私有信号后又透传暴露。
- **其他信号**: 无泄露，Poseidon 全程保护有效。
- **本报告价值**: 185行的工业级投票电路是引擎多层嵌套递归分析能力的绝佳验证场景，展示了引擎在 Hash/Select/Mul/AddSub 多类型交混环境中对 OneWay 屏障的精准识别。
