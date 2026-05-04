# 审计报告：CleanPegasus_zero-knowledge-puzzles IsZero

## 项目概述

| 字段 | 内容 |
|---|---|
| **项目名** | CleanPegasus_zero-knowledge-puzzles |
| **电路文件** | `IsZero/IsZero.circom` |
| **泄露类型** | 本轮复核为 0(0/0)（已退出 full 风险集合） |
| **受影响信号** | `in`（私有输入）|
| **论文价值** | 展示基础组件的"语境依赖安全性"：IsZero 作为子组件是安全的，独立实例化后因二元输出直接泄露 `in==0` 的真值；同时阐释 `<--` 不安全赋值与 Phase 1 污点传播的交互机制 |

---

## 本轮复核更新（2026-03-22）

- 检测计数由 `1(1/0)` 调整为 `0(0/0)`
- 本文保留作为历史误报/语境依赖分析样例，不再计入当前 full 风险清单

## 电路代码

```circom
pragma circom 2.1.6;

// If input is 0 return 1, else return 0

template IsZero() {
  signal input in;      // 私有
  signal output out;    // 公开

  signal inv;
  inv <-- in == 0 ? 1 : 1/in;    // ← 不安全赋值：inv 仅计算见证，无独立约束
  out <== 1 - in * inv;           // 约束：out = 1 - in*inv

  in * out === 0;                 // 附加约束（但 out=1-in*inv 已隐含此关系）
}

component main = IsZero();
```

此 `IsZero` 模板与 circomlib 官方版本逻辑等价，是 ZK 应用中最基础的组件之一，用于比较、条件分支等场景。本电路独立实例化为 `component main`，使 `out` 成为公开输出。

---

## ZKLeak 两阶段分析

### Phase 1：前向信息流传播

引擎在处理 `inv <-- ...` 时，虽然 `<--` 不生成约束，但引擎仍**追踪其计算图依赖**（`inv` 的值依赖 `in`），并在 Phase 1 中传播污点：

```
初始化：I(in) = {(in, Full)}

op_id 5  (Other):  inv  = in == 0 ? 1 : 1/in  → I(inv) = {(in, Full)}
op_id 9  (Mul):    t    = in * inv             → I(t)   = I(in) ⊎ I(inv) = {(in, Full)}
op_id 3  (Select): inv  = ternary(...)         → I(inv) = {(in, Full)}    [ternary select]
op_id 14 (Mul):    t'   = in * out             → I(t')  = {(in, Full)}    [for in*out===0]
op_id 16 (AddSub): out  = 1 - in*inv           → I(out) = {(in, Full)}
op_id 19 (Mul):    t''  = in * out             → I(t'') = {(in, Full)}
```

引擎调试日志：
```
DEBUG: Phase 1 output for sig_id 6  from op_id 5  (type: Other):   {(0, Full)}
DEBUG: Phase 1 output for sig_id 10 from op_id 9  (type: Mul):     {(0, Full)}
DEBUG: Phase 1 output for sig_id 11 from op_id 3  (type: Select):  {(0, Full)}
DEBUG: Phase 1 output for sig_id 15 from op_id 14 (type: Mul):     {(0, Full)}
DEBUG: Phase 1 output for sig_id 17 from op_id 16 (type: AddSub):  {(0, Full)}
DEBUG: Phase 1 output for sig_id 20 from op_id 19 (type: Mul):     {(0, Full)}
```

`inv` 通过 `<--` 赋值，但引擎将其建模为依赖 `in` 的计算节点（Other 类型），Full 污点得以传播。最终 `out` 的隐私信息集为 `I(out) = {(in, Full)}`。

---

### Phase 2：反向约束推理

初始化 `K(out) = FK`，将 `out` 加入工作列表。

**处理 `out`：**
- `I(out) = {(in, Full)}`，`K(out) = FK`
- 代数盲化检查：`I(out)` 中仅有单一私有变量 `in`，无盲化
- 结论：`K(in) ← FK`，Full Leak

**最终报告：**
```
warning: Private Input `in` has a FULL LEAK risk mapped to public outputs.
```

---

## 泄露严重性的精确分析

### Full Leak 的保守性

引擎报告 Full Leak，但从信息论角度来看，`out ∈ {0, 1}` 只能揭示 **1 bit** 关于 `in` 的信息：

| out 值 | 揭示的 in 信息 | 严重性 |
|---|---|---|
| `out = 1` | `in = 0`（精确）| **真正的 Full Leak** |
| `out = 0` | `in ≠ 0`（仅知 in 不为零）| Partial（约 1 bit） |

**为什么引擎判定为 Full Leak？**

ZKLeak Phase 2 的规则是：若 $I(z)$ 中有单一 Full 标签的私有变量，且 $K(z) = \mathbf{FK}$，则判定 Full Leak。引擎**不考虑函数的值域压缩**——即使 `out` 是二元信号，Full taint 仍意味着 `in` 的值通过确定性计算流入 `out`。

从**最坏情况**角度：当证明者生成 `out = 1` 的证明时，验证者立刻知道 `in = 0`，这是真实的 Full Leak。因此引擎的保守判定是有理由的。

---

## `<--` 不安全赋值的安全影响

```circom
inv <-- in == 0 ? 1 : 1/in;   // ← 不安全赋值，仅生成见证，不生成约束
out <== 1 - in * inv;          // 约束：out 由 inv 和 in 决定
```

circomspect 对此的警告：
```
warning: Using the signal assignment operator `<--` does not constrain the assigned signal.
  inv <-- in == 0 ? 1 : 1/in;
  The assigned signal `inv` is not constrained here.
  The signal `inv` is constrained here.  ← (out <== 1 - in * inv 对 inv 的间接约束)
```

**`<--` 的安全含义**：
- `inv` 没有独立的约束（没有 `inv * in === 1` 这样的约束当 `in ≠ 0` 时）
- 攻击者（恶意证明者）可以将 `inv` 设为任意值
- 若 `inv = 0`，则 `out = 1 - in * 0 = 1`，即使 `in ≠ 0`
- 结合 `in * out === 0`：如果 `out = 1`，约束 `in * 1 = 0` 强制 `in = 0`，这提供了部分保护
- 但约束系统实际上允许 `inv = 0`（不违反任何约束），从而使 `out` 不完全可信

**Circomlib 官方实现的对比**：Circomlib 的 IsZero 实现与本电路相同——这是 circomlib 的一个已知设计权衡，在实际应用中通过子电路上下文的外部约束保证正确性。

---

## 语境依赖安全性

IsZero 的安全性取决于使用语境：

### 安全场景：作为子组件（正确使用方式）

```circom
template ConditionalAdd() {
    signal input a;
    signal input b;
    signal output result;

    component isz = IsZero();
    isz.in <== a - b;
    // isz.out 是内部中间信号，不暴露为公开输出
    result <== isz.out * a + (1 - isz.out) * b;  // 用于内部条件选择
}

component main { public [a, b] } = ConditionalAdd();
```

在此场景中，`isz.out` 是中间信号，不是公开输出，因此不泄露 `a - b` 是否为零。

### 不安全场景：直接实例化（本案例）

```circom
component main = IsZero();
// out 成为公开输出，直接泄露 in == 0 的真值
```

---

## 与同项目其他电路的对比

| 电路 | 核心操作 | 泄露类型 | ZKLeak 阶段 I 输出 |
|---|---|---|---|
| `IsZero.circom` | `out = 1 - in*inv` | Full（保守） | `{(in, Full)}` via Other/Mul/AddSub |
| `Num2Bits.circom` | `out[i] <-- (in >> i) & 1` | Partial | `{(in, Partial)}` via 位提取（降级）|
| `StatefulComputation.circom` | `arr_out <== arr` | Full | `{(arr, Full)}` via 直接赋值 |

IsZero 的 Full taint（而非 Partial）是因为 `inv` 被建模为 `Other` 操作（包含整个三元表达式 `in == 0 ? 1 : 1/in`），其 Phase 1 输出被标记为 Full（而非 Partial），这与位提取操作不同。

---

## 修复建议

### 1. 不将 IsZero 独立实例化

IsZero 应作为内部子组件，不应独立地将 `out` 暴露为公开输出。

### 2. 若需证明"某值为零"，使用约束而非输出

```circom
// 正确：证明 in = 0，不通过 output 暴露
template ProveZero() {
    signal input in;
    in === 0;    // 直接约束，不需要泄露 out
}
```

### 3. 若需要布尔输出，使用 ZK-友好的哈希承诺替代

```circom
// 若需要公开"in 的某种属性"而不暴露 in 本身
component commitment = Poseidon(1);
commitment.inputs[0] <== in;
publicCommit <== commitment.out;   // 不可逆承诺
```

---

## 引擎能力评估

| 评估维度 | 结论 |
|---|---|
| 是否发现泄露 | ✅ 是（Full Leak 报告）|
| 是否正确处理 `<--` | ✅ 是（Other 操作类型追踪了 inv 与 in 的依赖）|
| 泄露严重性精度 | ⚠️ 保守（实际为 out=1 时 Full Leak，out=0 时 Partial）|
| 语境依赖安全性识别 | ❌ 未检测（引擎不区分"子组件使用"与"独立实例化"）|

---

## 总结

`IsZero.circom` 作为独立电路时，公开输出 `out` 揭示了 `in` 是否为零（当 `out = 1` 时完全揭露 `in = 0`）。ZKLeak 引擎通过 Phase 1 污点传播（追踪 `<--` 赋值的计算依赖）和 Phase 2 单变量检验，保守但合理地判定 Full Leak。

**论文核心启示**：基础组件（如 IsZero）的安全性是**语境依赖**的——作为子组件内部使用时安全，独立实例化时会创建信息泄露。这是 ZK 电路复用模式中的一个系统性设计风险，需要在组件接口规范层面加以防范。
