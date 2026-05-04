# 隐私泄露审计报告：CleanPegasus_zero-knowledge-puzzles (Num2Bits 位分解)

## 1. 项目与漏洞概述
- **项目名**: `CleanPegasus_zero-knowledge-puzzles`
- **泄露类型**: **1 Partial Leak (部分侧漏)**
- **涉及信号**: `num` (待分解的私有整数值)
- **检测依据**: BitExtract 操作链路产生 `{(0, Partial)}` 标记，最终累加步输出 `{(0, Partial), (0, Full)}`

---

## 2. 漏洞发生链路分析

### 审计目标电路：`CleanPegasus_zero-knowledge-puzzles\Num2Bits\Num2Bits.circom`

```circom
template Num2Bits(n) {
  signal input num;
  signal output out[n];       // ← 直接作为公开 OUTPUT！

  var acc = 0;
  var exp = 1;

  for (var i = 0; i<n; i++) {
    out[i] <-- (num >> i) & 1;       // 位提取：不安全赋值
    out[i] * (out[i] - 1) === 0;     // 二进制约束：out[i] ∈ {0,1}
    acc += out[i] * exp;
    exp = exp + exp;
  }

  acc === num;     // 重构约束：acc = Σ out[i] * 2^i = num
}

component main = Num2Bits(4);   // 实例化为 4 位分解
```

### 泄露机制

本电路将 `num` 的二进制表示通过 `signal output out[n]` **直接作为公开输出**暴露。泄露路径如下：

1. **位提取（BitExtract）**：`out[i] <-- (num >> i) & 1` 从私有输入 `num` 中逐位提取，每个 `out[i]` 个体均携带 `num` 的第 i 位信息 → `{(0, Partial)}`
2. **重构约束（acc === num）**：`acc = out[0]·1 + out[1]·2 + out[2]·4 + out[3]·8 = num` 确定性地将全部输出 bits 与 `num` 绑定。
3. **Output 公开**：`out[0..3]` 均为 `signal output`，公开可见。

由于 `acc === num`，知道所有 `out[i]` 等价于完全知道 `num`：
$$\text{num} = \sum_{i=0}^{3} \text{out}[i] \cdot 2^i$$

引擎通过分析 BitExtract → AddSub → Mul 的操作链，将最终约束步标记为 `{(0, Partial), (0, Full)}`，最终判定为 **Partial Leak**（保守分类，因为位提取操作链的中间步骤均为 Partial）。

### 为何这是论文中的典型案例

**Num2Bits 是 circomlib 中最基础、使用最广泛的组件之一**，几乎所有范围检查（RangeCheck）都依赖它。核心问题在于使用者的两种截然不同的模式：

| 用法 | `out` 的类型 | 隐私结果 |
|------|------------|---------|
| ✅ 正确：作为中间信号用于范围约束 | `signal`（中间） | 不泄露 `num` |
| ❌ 错误：本案例将 bits 作为公开输出 | `signal output`  | `num` 被位级完整重建 |

当开发者将 Num2Bits 的输出 bits 作为公开输出暴露时，私有整数 `num` 的所有 n 位均被完整泄露。这揭示了 **ZK 电路复用基础组件时的语境依赖性安全陷阱**：相同的 Num2Bits 逻辑，在中间信号语境下安全，在输出信号语境下不安全。

此外，本电路还存在另一个安全警告：`out[i] <--` 使用了**不安全赋值操作符**（`<--` 而非 `<==`），仅赋值而不约束，依赖后续 `acc === num` 补充约束。这是 circom 中的经典 under-constrained 模式。

---

## 3. 审计结论：确认为有效泄露 (True Positive)

这是一个具有**教学示范价值**的隐私泄露案例：开发者将 Num2Bits 的输出 bits 暴露为公开输出，导致私有整数 `num` 通过重构约束完全泄露（4 位范围内的 Full Leak，整体判定为 Partial）。

该案例对论文的核心价值：
1. **基础组件的语境依赖性**：Num2Bits 本身无问题，但输出信号语义决定了隐私安全性
2. **Partial Leak 的实质含义**：在 4 位分解场景中，Partial Leak 实际上意味着 `num ∈ [0,15]` 的域内完全确定
3. **`<--` 赋值操作符的隐患**：不安全赋值是 circom 独有的风险点，circomspect 可同时捕捉两类缺陷

**True Positive**（有效泄露）。
