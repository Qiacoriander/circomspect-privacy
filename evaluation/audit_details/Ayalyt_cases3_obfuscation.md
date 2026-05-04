# 隐私泄露审计报告：Ayalyt cases/3/temp1 & temp2（约束混淆技术下的 Partial Leak 复核）

## 1. 项目与漏洞概述

- **项目名**: `Ayalyt_blockchain-Verification-Integration`
- **涉及文件**: `compiler-testing/cases/3/temp1.circom`（L72）、`cases/3/temp2.circom`（L73）
- **泄露类型**: **Partial Leak（各 1 处）**
- **特征**: 超大规模混淆电路（700+ 信号，1000+ 操作节点）中，核心泄露约束被**代数恒等式**和**域阶幂运算**伪装，ZKLeak 引擎仍成功识别

## 1.1 本轮复核更新（2026-03-22）

- `temp1.circom`：由 `1(1/0)` 调整为 `1(0/1)`
- `temp2.circom`：由 `1(1/0)` 调整为 `1(0/1)`
- 结论：风险仍存在，但在本轮比较语义调整后由 Full 降级为 Partial

---

## 2. 电路结构概述

两个文件均定义了一个深度混淆的主模板（约 400-500 行），包含：
- 大量随机命名的中间信号（如 `GwgIkpPzK0IC`, `d3ZS9nNOUMFF`, `U0H8HM5RAOto`）
- 嵌套子组件 `ASjLBk8vHA4s` 和 `ASjLBk8vHA4s.B7qYCMRWWt6g[0][0]`
- 私有输入 `OgPXMuq0UhNt[1][1][1]`（3D 数组信号）
- 大量无效/冗余约束和未使用信号

**主组件**：`component main = O3h4P1AWedYt()` （同一模板名，两文件一致）

---

## 3. 核心泄露约束：零系数恒等式（L72）

### 3.1 关键约束

```circom
signal GwgIkpPzK0IC;
GwgIkpPzK0IC <== (0 * (ASjLBk8vHA4s.B7qYCMRWWt6g[0][0] - OgPXMuq0UhNt[0][0][0])
                  + OgPXMuq0UhNt[0][0][0]);
```

### 3.2 代数化简

$$\text{GwgIkpPzK0IC} = 0 \times (\underbrace{ASjLBk8vHA4s.\text{B7qYCMRWWt6g}[0][0] - OgPXMuq0UhNt[0][0][0]}_{\text{看似复杂的噪声项}}) + OgPXMuq0UhNt[0][0][0]$$

$$= OgPXMuq0UhNt[0][0][0]$$

**零系数混淆**：`0*(任何表达式) = 0`，整个减法项被消零，结果恒等于私有输入 `OgPXMuq0UhNt[0][0][0]`。

### 3.3 为何引擎能检测

**Phase 1 追踪**：乘以 0 的节点产生 `Other→{(731, Full)}`（sig 731 = `OgPXMuq0UhNt`），随后 AddSub 节点继续传播：
```
Other→{(731,Full)} → Select→{(731,Full)} → AddSub→{(731,Full)} → ... → 输出信号 GwgIkpPzK0IC
```
引擎的符号运算正确识别出：即使存在大量中间项，最终约束等价于 `GwgIkpPzK0IC = OgPXMuq0UhNt`。

**Phase 2**：`GwgIkpPzK0IC` 出现在公开约束路径中，且 `K(GwgIkpPzK0IC) = {(OgPXMuq0UhNt, Full)}`，单变量确定性关系 → **Full Leak 确认**。

---

## 4. 域阶幂运算混淆（L73 增量）

### 4.1 关键约束

```circom
GwgIkpPzK0IC <== (0 * (ASjLBk8vHA4s.B7qYCMRWWt6g[0][0] - OgPXMuq0UhNt[0][0][0])
                  + OgPXMuq0UhNt[0][0][0])
                + 21888242871839275222246405745257275088548364400416034343698204186575808495617;
```

### 4.2 BN128 域阶幂运算恒等式

BN128 椭圆曲线的有限域阶（素数）为：

$$p = 21888242871839275222246405745257275088548364400416034343698204186575808495617$$

由费马小定理，在 $\mathbb{F}_p$ 中：$\forall x: x + p \equiv x \pmod{p}$

因此：

$$\text{GwgIkpPzK0IC} = OgPXMuq0UhNt[0][0][0] + p \equiv OgPXMuq0UhNt[0][0][0] \pmod{p}$$

**域阶加法混淆**：加上域阶 $p$ 在 $\mathbb{F}_p$ 中等价于加 0，约束语义完全不变。此技巧与另一常见变体 `2^p` 计算等效（BN128 中 $2^p \equiv 2 \pmod{p}$，`x + 2^p ≡ x + 2 ≠ x`，但直接加 $p$ 确实是零偏移）。

### 4.3 Phase 1 表现

L73 比 L72 多出若干 AddSub 节点（对应加法链的额外计算），但 {(731, Full)} 污点链最终不变，结论相同：**Full Leak**。

---

## 5. 攻击场景

两个文件中，`GwgIkpPzK0IC` 信号出现在公开输出的约束路径中。具体地：
- `d3ZS9nNOUMFF[0] <== (OgPXMuq0UhNt[0][0][0] + ASjLBk8vHA4s.vS05Bonf7LGM) - U0H8HM5RAOto`

结合 `GwgIkpPzK0IC = OgPXMuq0UhNt[0][0][0]`，验证者可从多个公开输出的线性组合直接恢复私有输入 `OgPXMuq0UhNt`。

---

## 6. 与其他混淆手法的对比

| 混淆技术 | 代数形式 | 引擎识别方式 |
|---------|---------|------------|
| 零系数（L72） | `0*(a-b)+b = b` | Phase 1 Other→Full（零乘任何值=0，剩余原值） |
| 域阶加法（L73）| `b + p ≡ b` (mod p) | Phase 1 AddSub→Full（常数偏移不改变污点） |
| 1倍数乘法（其他案例）| `1*b = b` | Phase 1 Mul→{Full}（单变量因子） |
| var 中间变量（其他案例）| `var v=b; a<==v` | Phase 1 直接传播（var 展开后等同于信号引用） |

**核心结论**：所有这些代数混淆手法在 R1CS 约束多项式框架下均等价于原始约束。ZKLeak 的 Phase 1/2 符号分析作用在约束多项式上，而非源代码语法层，因此混淆代码无法欺骗引擎。

---

## 7. 审计结论

- **L72** (`cases/3/temp1.circom`)：确认为有效泄露，10 条 issues，1 处 Full Leak
- **L73** (`cases/3/temp2.circom`)：确认为有效泄露，10 条 issues，1 处 Full Leak（额外域阶混淆无效）
