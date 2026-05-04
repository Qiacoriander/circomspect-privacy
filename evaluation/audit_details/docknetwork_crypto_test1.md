# 审计报告：docknetwork_crypto Test1（低次多项式 Full Leak）

## 项目概述

| 字段 | 内容 |
|---|---|
| **项目名** | docknetwork_crypto (LegoGroth16 测试向量) |
| **电路文件** | `legogroth16/test-vectors/circuits/test1.circom` |
| **泄露类型** | Full Leak |
| **受影响信号** | `x`（私有输入）|
| **论文价值** | 揭示"非线性约束不等于隐私保护"：低次多项式在有限域上可通过标准算法高效求根，Full Leak 通过 ZKLeak 两阶段算法正确识别 |

---

## 电路代码

```circom
pragma circom 2.0.0;

/* This circuit template checks that y = x^3 + x + 5. */

template Test1 () {
    signal input x;    // 私有
    signal output y;   // 公开

    signal t1 <== x * x;      // t1 = x²
    signal t2 <== t1 * x;     // t2 = x³
    y <== t2 + x + 5;         // y = x³ + x + 5
}

component main = Test1();
```

此电路是 **LegoGroth16** 证明系统的测试向量之一，也是 circom 官方文档中"intro to ZK proofs"的标准示例电路，用于验证证明者知道满足 `y = x³ + x + 5` 的 `x`，而不直接透露 `x`。

---

## ZKLeak 两阶段分析

### Phase 1：前向信息流传播

按 CCIG 的拓扑顺序逐操作节点传播隐私信息集 $\mathcal{I}(s)$：

```
初始化：I(x) = {(x, Full)}

op_id 3  (Mul):   t1 = x * x    → I(t1) = I(x) ⊎ I(x) = {(x, Full)}
op_id 7  (Mul):   t2 = t1 * x   → I(t2) = I(t1) ⊎ I(x) = {(x, Full)}
op_id 10 (AddSub): _  = t2 + x  → I(...) = {(x, Full)} ⊎ {(x, Full)} = {(x, Full)}
op_id 13 (AddSub): y  = ... + 5 → I(y)  = {(x, Full)}
```

引擎调试日志确认：
```
DEBUG: Phase 1 output for sig_id 4  from op_id 3  (type: Mul):    {(0, Full)}
DEBUG: Phase 1 output for sig_id 8  from op_id 7  (type: Mul):    {(0, Full)}
DEBUG: Phase 1 output for sig_id 11 from op_id 10 (type: AddSub): {(0, Full)}
DEBUG: Phase 1 output for sig_id 14 from op_id 13 (type: AddSub): {(0, Full)}
```

关键设计规则（来自 ZKLeak 方案文档）：
- **线性/仿射变换**：`y ← a·x + b`（a≠0），$\mathcal{I}(y) \gets \mathcal{I}(x)$，Full 保持不降级。
- **混合操作**：`y ← x₁ + x₂`，$\mathcal{I}(y) \gets \mathcal{I}(x_1) \uplus \mathcal{I}(x_2)$，合并集合。

`t1 = x * x` 中 `x` 同时作为两个乘数输入，合并后仍为 `{(x, Full)}`（集合元素去重）。`x` 的 Full 标签全程保持不降级。

---

### Phase 2：反向约束推理

初始化 `K(y) = FK`（y 为公开输出），将 `y` 加入工作列表。

**处理 `y`：**
- `I(y) = {(x, Full)}`，`K(y) = FK`
- **代数盲化安全检查**：$\mathcal{I}(y)$ 中仅有 **一个** 具有 Full 标签的私有变量 `x`，无其他私有变量与之混合
- 结论：无代数盲化，`K(x) ← FK`，将 `x` 加入工作列表

```
I(y) = {(x, Full)}  →  单一变量  →  无盲化  →  K(x) = FK
```

**最终报告：**
```
L_full = {x}   (Full Leak)
L_part = {}
```

---

## 为什么 x 真的会泄露？

### 论点：y = x³ + x + 5 看起来是非线性的

初看之下，`y = x³ + x + 5` 是一个三次多项式，似乎比线性函数更安全。但在有限域上，这种"安全感"是错误的。

### 有限域上的多项式求根

设 BN254 的素数域为 $\mathbb{F}_p$，其中：
```
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```

给定公开的 $y$ 值，攻击者需要在 $\mathbb{F}_p$ 上求解：

$$f(x) = x^3 + x + (5 - y) = 0$$

在有限域 $\mathbb{F}_p$ 上，**多项式求根可以高效完成**，主要算法有：

| 算法 | 复杂度 | 适用范围 |
|---|---|---|
| **Cantor-Zassenhaus** | $O(\deg^2 \cdot \log p)$ | 最常用，随机化算法 |
| **Berlekamp** | $O(\deg^3 + \deg^2 \cdot \log p)$ | 确定性算法 |
| **Tonelli-Shanks** (特殊情况 deg=2) | $O(\log^2 p)$ | 平方根 |

对于度数为 3 的多项式 `f(x)` 在 $\mathbb{F}_p$ 上：
1. 计算 `gcd(f(x), x^p - x)` 找到所有根（费马小定理：所有 $\mathbb{F}_p$ 元素满足 $x^p = x$）
2. 通过 DDF（不同度分解）和 EDF（等度分解）找到具体根

**结论：** 给定 $y$，攻击者可以在 $O(\log^2 p)$（约 508² ≈ 258,000 次域运算）内求解 $x$，这是**多项式时间**算法，完全可行。

### 候选解的数量

$f(x) = x^3 + x + (5-y) = 0$ 在 $\mathbb{F}_p$ 上至多有 3 个根：
- **0 个根**：不可能（电路合法执行意味着 y 来自某个 x）
- **1 个根**：直接恢复 x，Full Leak 完全确定
- **3 个根**：攻击者得到 3 个候选值，可通过上下文进一步排除

---

## 与线性 Full Leak 的比较

| 对比维度 | 线性 Full Leak (`y = 5x`) | 本案例 (`y = x³ + x + 5`) |
|---|---|---|
| **求逆公式** | `x = y × 5⁻¹ mod p`（单步） | `f(x) = 0` → Cantor-Zassenhaus（多步）|
| **计算复杂度** | O(log p)（扩展欧几里得）| O(log² p)（多项式求根）|
| **候选解数量** | 唯一 | 至多 3 个 |
| **ZKLeak 判定** | Full Leak | Full Leak |
| **实际安全性** | 完全不安全 | 完全不安全（仅多几步计算）|

---

## ZKLeak 分析的关键洞察

ZKLeak 对此类情形的判定依据（来自方案文档 Phase 2 规则）：

> 如果 $(p, \mathsf{Full}) \in \mathcal{I}(z)$ 且 $\mathcal{K}(z) = \mathbf{FK}$，且 $\mathcal{I}(z)$ 中只有**单一**私有变量，则将 `p` 的知识状态升级为 $\mathbf{FK}$。

本案例中 `I(y) = {(x, Full)}`，只有 `x` 一个私有变量，无代数盲化，直接判定 Full Leak。**引擎的判定与实际攻击可行性完全一致**。

---

## 为什么这个电路会被误用？

`y = x³ + x + 5` 是 circom 官方文档中介绍 ZK 证明系统的第一个示例电路：

> "We will use the following circuit to illustrate the basic concepts of ZK proofs: `y = x³ + x + 5`."

许多开发者初学 ZK 时会误解这个电路的用途：他们认为"因为 y 是由 x 通过复杂运算得到的，所以 x 是安全的"。但实际上，**这个电路的设计目的从来就不是隐藏 x**——它只是演示如何在 R1CS 中表达多项式约束。

将 `x` 声明为私有输入（未配置 `{ public [x] }`）的行为，在追求隐私时会造成虚假安全感。

---

## 修复建议

1. **明确 x 的公开性**：如果 x 本就不需要保密，应声明为公开输入：
   ```circom
   component main { public [x] } = Test1();
   ```

2. **若 x 确实需要保密，不应将 y 公开**：y 是 x 的低次多项式，可高效求逆。

3. **使用单向函数**：若需要在不暴露 x 的前提下验证 x 满足某条件，应使用哈希承诺：
   ```circom
   component h = Poseidon(1);
   h.inputs[0] <== x;
   commitment <== h.out;   // 公开 commitment = Poseidon(x)，不可逆
   ```

---

## 总结

`test1.circom` 是一个经典的"初学者陷阱"电路：三次多项式看似非线性，实则在有限域上完全可逆（通过多项式求根算法）。ZKLeak 的两阶段算法正确地通过 Phase 1 污点传播（Full taint 全程不降级）和 Phase 2 单变量检验（无代数盲化）判定 Full Leak，与实际攻击可行性完全吻合。

**本案例的核心启示**：在 ZK 电路设计中，"使用了非线性约束"不等同于"提供了隐私保护"。只有**单向函数**（如 Poseidon、SHA256 等密码学哈希）才能真正阻断信息的反向推导。
