# 审计报告：MAKMED1337_ZKP-circom BuildMerkleTree（误报分析）

## 项目概述

| 字段 | 内容 |
|---|---|
| **项目名** | MAKMED1337_ZKP-circom |
| **电路文件** | `circuits/merkleTree/buildMerkleTree.circom` |
| **引擎报告** | Full Leak（`leaves` 泄露至 `root`） |
| **审计结论** | **误报（False Positive）** |
| **误报类型** | 哈希函数原像安全性盲区 |
| **论文价值** | 揭示 CCIG-Leak 引擎的系统性局限：无法区分"计算可逆函数（真泄露）"与"抗原像哈希函数（误报）"；为引擎改进方向提供明确的反例证据 |

---

## 电路功能描述

`BuildMerkleTree` 接受 `2^levels` 个叶节点作为私有输入，通过逐层哈希构建完整 Merkle 树，并输出树根 `root`。

```circom
template BuildMerkleTree(levels, index) {
    var totalLeaves = 2 ** levels;

    signal input leaves[totalLeaves];   // 私有：叶节点数据
    signal output root;                  // 公开：Merkle 树根

    var numHashers = totalLeaves - 1;
    component hashers[numHashers];

    for (var i = 0; i < numHashers; i++) {
        hashers[i] = HashLeftRight();    // ← 关键：使用 Poseidon 哈希
    }

    // 将叶节点接入底层哈希器
    for (var i = 0; i < numLeafHashers; i++){
        hashers[i].left  <== leaves[i*2];
        hashers[i].right <== leaves[i*2+1];
    }

    // 逐层哈希
    for (var i = numLeafHashers; i < numLeafHashers + numIntermediateHashers; i++) {
        hashers[i].left  <== hashers[k*2].hash;
        hashers[i].right <== hashers[k*2+1].hash;
        k++;
    }

    root <== hashers[numHashers - 1].hash;
}

component main = BuildMerkleTree(4, 5);  // 16 个叶节点
```

`HashLeftRight` 的实际定义（来自 `incrementalMerkleTree.circom`）：

```circom
template HashLeftRight() {
    signal input left;
    signal input right;
    signal output hash;
    hash <== Poseidon(2)([left, right]);   // ← Poseidon 密码学哈希
}
```

---

## 引擎报告

```
circomspect: 从 main component 'BuildMerkleTree' 开始分析，公开输入：[]

warning: Private Input `leaves` has a FULL LEAK risk mapped to public outputs.
   ┌─ buildMerkleTree.circom:16:5
   │
16 │     signal input leaves[totalLeaves];
   │     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ This private input completely leaks
   │     its exact value via deterministic relation constraints.
   │
   = https://github.com/trailofbits/circomspect/.../ccig-leak.

circomspect: 4 issues found.
```

引擎同时报告了3个"变量赋值后未使用"警告（针对 `h` 计数器），以及1个 CCIG-Leak 警告。

---

## 误报分析

### 为什么引擎报告了 Full Leak？

CCIG-Leak 引擎通过**约束图可达性**分析判断泄露：

1. `root` 是公开输出（public signal output）
2. `root` 通过约束方程确定性地依赖于 `hashers[numHashers-1].hash`
3. `hashers[i].hash` 确定性地依赖于其输入 `left` 和 `right`
4. 最终追溯至叶节点 `leaves[0..15]`（私有输入）

由此，引擎判定：**`leaves` 通过确定性约束链决定了 `root`，因此 `leaves` "泄露"于 `root`**。

但这个推理方向**与零知识证明的泄露方向相反**。

---

### 泄露方向的核心错误

| 方向 | 含义 | 正确性 |
|---|---|---|
| `leaves → root`（约束方向） | 给定 `leaves`，可唯一确定 `root = hash(leaves)` | ✅ 正确（Poseidon 是确定性函数） |
| `root → leaves`（信息泄露方向） | 给定公开的 `root`，验证者能否推算出 `leaves`？ | ❌ 不可能（Poseidon 抗原像） |

**零知识证明的隐私保证**是从验证者视角出发的：验证者只能看到 `root`，并依此判断证明者是否拥有某组满足条件的叶节点，但**无法从 `root` 反推具体的叶节点值**。

---

### Poseidon 哈希的密码学保证

`Poseidon` 是一种专为 ZK 证明系统设计的密码学海绵哈希函数，具备以下安全性质：

| 安全性质 | 含义 | 对本案例的影响 |
|---|---|---|
| **抗原像（Preimage Resistance）** | 给定 `h = Poseidon(x, y)`，无法高效还原 `x, y` | `root` 不揭示叶节点 ✅ |
| **抗第二原像** | 给定 `x`，无法找到 `x'` 使 `Poseidon(x') = Poseidon(x)` | Merkle 树结构可信 ✅ |
| **抗碰撞** | 无法找到两对不同的输入得到相同输出 | Merkle 路径验证安全 ✅ |

因此，虽然 `root = f(leaves)` 中 `f` 是确定性函数，但 `f` 是**单向的**（计算不可逆），验证者从 `root` 获得的信息量接近于零（忽略集合成员性验证本身的语义）。

---

### Phase 1 污点输出：引擎对哈希的处理

观察引擎的调试输出：

```
DEBUG: Phase 1 output for sig_id 11 from op_id 10 (type: Mul):   {}
DEBUG: Phase 1 output for sig_id 17 from op_id 16 (type: AddSub): {}
DEBUG: Phase 1 output for sig_id 25 from op_id 24 (type: AddSub): {}
DEBUG: Phase 1 output for sig_id 35 from op_id 34 (type: Select):  {}
...（所有 Phase 1 输出均为空集 {}）
```

所有信号的 Phase 1 污点集合均为 `{}`（空），包括 Poseidon 内部的乘法和加法操作。这表明**引擎在污点传播阶段实际上未追踪到任何私有输入污染**。

然而最终仍生成了 Full Leak 警告。推断原因：引擎在 Phase 2（约束图分析阶段）独立判断了 `root` 与 `leaves` 之间的约束可达性，绕过了 Phase 1 的污点结果。

这揭示了引擎架构的一个问题：**Phase 1 的污点传播和 Phase 2 的约束图可达性分析使用了不同的假设，在密码学哈希组件上产生了矛盾的结论**。

---

## 与真实 Full Leak 的对比

为便于理解，对比一个**真实** Full Leak 案例（以 `Kartikvyas1604_TrustNet` 为参照）：

| 对比维度 | 真实 Full Leak（TrustNet） | 误报（BuildMerkleTree） |
|---|---|---|
| **关键约束** | `nullifier <== employeeSecret * 2` | `root <== Poseidon(leaves[0], leaves[1])...` |
| **函数类型** | 线性乘法（域内可逆）| 密码学哈希（不可逆）|
| **攻击复杂度** | O(1)：`employeeSecret = nullifier / 2` | 2^128+（Poseidon 安全参数）|
| **验证者信息增益** | 完全获得 `employeeSecret` | 零（仅知根存在） |
| **正确结论** | 确认为有效 Full Leak | **误报** |

---

## 引擎改进建议

本案例展示了 CCIG-Leak 引擎的一个系统性局限，可通过以下方式改进：

### 方案一：哈希组件白名单

对已知密码学安全的哈希组件（Poseidon、MiMC、SHA256、Pedersen 等）建立白名单，**在约束图可达性分析中不视其为信息透传路径**：

```rust
// 伪代码示例
fn is_opaque_hash_component(comp_name: &str) -> bool {
    matches!(comp_name, "Poseidon" | "MiMC" | "Sha256" | "Pedersen")
}
```

### 方案二：引入计算不可逆性标注

在 CCIG 图模型中为节点添加"可逆性"属性：
- **可逆节点**（如加法、乘法常数、选择器）：传播污点
- **不可逆节点**（如密码学哈希）：**阻断**污点传播，不视为泄露路径

### 方案三：分离"约束可达"与"信息泄露"判定

当前引擎混淆了"约束系统中 A 决定 B"与"观察 B 可推断 A"两个概念。改进方向是引入**计算难度**的估计，只有当约束函数的逆函数是多项式时间可计算时，才判定为泄露。

---

## 结论

`BuildMerkleTree.circom` 的 Full Leak 警告是**误报**。引擎正确识别了 `leaves → root` 的约束依赖关系，但错误地将其等同于"root 揭示 leaves"的隐私泄露。由于 `HashLeftRight` 使用 Poseidon 哈希（一种抗原像的密码学哈希函数），从公开的 `root` 出发**在计算上不可能**还原私有的 `leaves`。

本误报对论文具有重要价值：它为 CCIG-Leak 引擎的改进提供了**具体的技术反例**，并指明了引入"哈希原像安全性感知"能力的必要性。
