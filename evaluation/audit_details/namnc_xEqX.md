# 审计报告：namnc_circom-2-arithc / xEqX.circom

## 项目概览

| 字段 | 内容 |
|---|---|
| 项目 | namnc_circom-2-arithc |
| 文件 | `tests/circuits/integration/xEqX.circom` |
| 引擎判定 | 本轮为 Partial 告警（`1(0/1)`） |
| 人工审计结论 | **误报（False Positive）** |
| 误报类别 | 比较恒等式（Comparison Tautology） |
| 论文价值 | 揭示引擎第三类误报机理；与Poseidon误报（单向函数）和公开信号误判在根因上完全不同 |

---

## 本轮复核更新（2026-03-22）

- 检测计数由 `1(1/0)` 调整为 `1(0/1)`
- 尽管告警强度由 Full 降为 Partial，但 `x==x` 恒等式导致的误报根因不变

## 原始电路代码

```circom
pragma circom 2.1.0;

template xEqX() {
    signal input x;
    signal output out;

    out <== x == x;
}

component main = xEqX();
```

---

## 引擎输出日志

```
circomspect: 从 main component 'xEqX' 开始分析，公开输入：[]
DEBUG: Phase 1 output for sig_id 3 from op_id 2 (type: Other): {(0, Full)}
warning: Private Input `x` has a FULL LEAK risk mapped to public outputs.
   ┌─ xEqX.circom:4:5
   │
4  │     signal input x;
   │     ^^^^^^^^^^^^^^ This private input completely leaks its exact value via deterministic relation constraints.

circomspect: 1 issue found.
```

---

## 语义分析：out 是常量 1

`x == x` 是一个**比较恒等式（Comparison Tautology）**：任意值 $x$ 与自身比较，结果永远为 `true`，在 Circom 布尔语义下对应整数 **1**。

因此：

$$\text{out} = (x == x) = 1 \quad \forall x \in \mathbb{F}_p$$

公开输出 `out` 是与 $x$ 完全无关的常量。从信息论角度：

$$H(x \mid \text{out}) = H(x \mid 1) = H(x)$$

观察者看到 `out = 1` 后，对 $x$ 的不确定性**没有任何减少**。Full Leak 判定不成立。

---

## ZKLeak 两阶段分析过程

### Phase 1（前向信息流传播）

| 信号 ID | 操作 | 操作类型 | Phase 1 输出（$\mathcal{I}(s)$） |
|---|---|---|---|
| sig_id 0 | 私有输入 `x` | — | $\{(0, \text{Full})\}$ |
| sig_id 3 | `x == x`（运算 op_id 2） | **Other** | $\{(0, \text{Full})\}$ |

关键环节：引擎将 `x == x` 编译为一个 **Other** 类型操作。Other 类型是引擎对无法精确分类的操作（包括 `<--` 赋值、比较运算符等）的**保守处理策略**：直接将输入信号的污点集原样传播到输出。

因此 sig_id 3（即 `out`）继承了 $x$（sig_id 0）的 Full 污点，Phase 1 输出：

$$\mathcal{I}(\text{out}) = \{(x,\ \text{Full})\}$$

### Phase 2（反向约束推理）

工作列表算法以公开信号 `out` 为起点：

1. `out` 是 signal output，标记为**已知（FK）**
2. 查找 `out` 的约束：`out === (x == x)`（引擎视为 `out` 与某包含 `x` 的表达式相关联）
3. 查找 $\mathcal{I}(\text{out})$ = $\{(x, \text{Full})\}$，仅含**一个私有变量** $x$
4. **代数盲化检查**：$|\mathcal{I}(\text{out})| = 1$，无其他变量可提供盲化
5. 结论：$K(x) = \text{FK}$（Full Known）

引擎的推理链在逻辑上内部自洽——问题不在于 Phase 2 的推理规则，而在于 **Phase 1 传入了错误的污点信息**。

---

## 误报根因：引擎无法识别比较恒等式

### Other 操作类型的保守语义

ZKLeak 引擎将操作类型分为：
- **AddSub**：加减法，线性，Full 污点不变传递
- **Mul**：乘法，二次，Full 污点不变传递
- **Hash**：哈希函数，传播为 OneWay 标签
- **BitExtract**：位提取，降级为 Partial 标签
- **Select**：条件选择，按最悲观路径传播
- **Other**：所有无法精确分类的操作，**保守地传播 Full 污点**

比较运算 `==` 被归入 Other 类型。Other 的保守策略对于大多数操作是合理的（如未知函数应当最坏情况分析），但对于**自引用比较**（`x == x`）却产生误报。

### 本质区别：常量输出 vs One-Way 函数

| 误报类别 | 典型案例 | 误报原因 | out 的信息论性质 |
|---|---|---|---|
| **单向函数（Hash）** | `MAKMED1337/buildMerkleTree.circom` | 引擎不识别 Poseidon 不可逆性 | $H(x \mid \text{out}) > 0$，但 out→x 在计算上不可行 |
| **公开信号误判** | `semaraugusto/backbone_wo_hashing.circom` | 引擎未继承 main 组件公开属性 | 信号本身就是公开输入，不应参与泄露分析 |
| **比较恒等式（本案）** | `namnc/xEqX.circom` | 引擎不识别 `x == x` 为常量表达式 | $H(x \mid \text{out}) = H(x)$，**out 是常量**，无信息 |

Poseidon 误报中，`out` 是 $x$ 的函数（虽然不可逆）；本案中，`out` 根本不是 $x$ 的函数——它是与 $x$ 无关的常量 **1**。这是比 Poseidon 误报更"严重"的误报：即使从信息论层面，也不存在任何泄露。

---

## 电路背景

`xEqX.circom` 是 `namnc/circom-2-arithc`（Circom 到算术电路转换工具）的**集成测试用例**，专门用于测试编译工具链能否正确处理比较运算符。该电路本身没有隐私保护意图，是工具链功能测试的最小用例。

同项目中的三个测试电路均被引擎标记为泄露：

| 文件 | 电路 | 实际情况 |
|---|---|---|
| `addZero.circom` | `out <== in + 0` | 真正Full Leak（加零等价于直通） |
| `mainTemplateArgument.circom` | `out <== in + 100` | 真正Full Leak（线性偏移可反算） |
| `xEqX.circom` | `out <== x == x` | **误报**（恒为1，无信息泄露） |

---

## 改进建议

### 短期：编译期常量传播

在 Phase 1 之前增加**符号常量传播（Symbolic Constant Propagation）**阶段：

```
IF 表达式 E 包含形如 (s == s) / (s - s) / (s * 0) 的子表达式
THEN 在污点传播前将其折叠为常量
```

对于 `x == x`，识别两侧为同一信号后，直接替换为常量 `1`，后续污点传播不涉及 `x`。

### 长期：信息论感知的 Other 处理

为 Other 类型操作增加**结构化子分析**：
1. 对比较运算（`==`, `!=`, `<`, `>`），分析两侧操作数是否相同
2. 对 `a == a` 形式（两侧为同一信号），输出 $\mathcal{I} = \emptyset$（空污点集）
3. 推广到 `a - a`（恒为0）、`a * 0`（恒为0）等模式

---

## 总结

`namnc/xEqX.circom` 案例揭示了 ZKLeak 引擎的第三类误报来源：**比较恒等式（Comparison Tautology）**。引擎将 `x == x` 视为 Other 类型操作，保守地传播 Full 污点，但数学上 `out = (x == x) = 1` 是常量，与 $x$ 完全无关。这与 Poseidon 哈希误报（计算不可逆性）和公开信号误判（AST作用域）形成了三种不同机理的误报体系，共同构成 ZKLeak 引擎假阳性分析的完整分类框架。
