# 隐私泄露审计报告：HoYongJin_zk-vote

## 1. 项目与漏洞概述
- **项目名**: `HoYongJin_zk-vote`
- **泄露类型**: **1 Full Leak (完全侧漏)**
- **涉及信号**: `root_in` (Merkle 树根)
- **安全幸存信号**: `user_secret` (用户秘钥), `vote` (投票选择), `election_id` (选举ID) 等**均未泄漏**

---

## 2. 漏洞发生链路分析

### 审计目标电路：`HoYongJin_zk-vote\server\zkp\circuits\VoteCheck.circom`

这是一个功能完备、设计精良的**零知识匿名投票系统**（185行）。它包含了：
- **MerkleProof**：证明投票者在注册选民树中的存在
- **VoteProof**：验证投票格式（1-hot编码）、计算选票索引、生成唯一 Nullifier 防止双重投票

架构上堪称教科书级别的 ZK 应用，但有一个小问题：

#### Full Leak: root_in 的"回声"设计
```circom
template Main(depth, numOptions) {
    signal input root_in;     // 注释里写了 "Public"...
    signal output root_out;   // 注释里写了 "Public"...

    root_out <== root_in;     // "回声"赋值
}
component main = Main(3, 3);  // 没有写 {public [root_in]}
```
作者在注释中清楚标注了 `root_in` 是 Public（因为 Merkle 树根本身就是链上公开知识），并且设计了一个 `root_out` 来"回声"这个值以便合约验证。然而由于组件实例化时遗漏了 `{public [root_in]}`，引擎将 `root_in` 判定为隐私数据，随后的 `root_out <== root_in` 便触发了 Full Leak。

#### 引擎的精准表现
- `user_secret` 经 Poseidon 哈希后生成 leaf → **未泄漏** ✅
- `vote[numOptions]` 经 1-hot 编码和加权求和后得到 `vote_index` → **未泄漏** ✅  
- `election_id` 经 Poseidon 与 user_secret 联合哈希后生成 nullifier → **未泄漏** ✅
- `pathElements/pathIndices` 仅参与 Merkle 计算 → **未泄漏** ✅

只有 `root_in` 这一个遗漏白名单声明的变量被精准锁定。

## 3. 审计结论：确认为有效泄露 (True Positive)
这个案例极其有价值：它展示了一个**在密码学和安全设计上near-perfect的真实投票应用**中，仅因为一个白名单声明的语法遗漏就被引擎准确捕获。同时引擎对投票秘钥、选票内容、选举ID等真正敏感数据全部"放行"（不误报），展示了工具在复杂真实场景中的高精准度。**True Positive**。
