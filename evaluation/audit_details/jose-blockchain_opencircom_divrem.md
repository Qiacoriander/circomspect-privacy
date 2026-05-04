# 隐私泄露审计报告：jose-blockchain_opencircom (除余测试电路)

## 1. 项目与漏洞概述
- **项目名**: `jose-blockchain_opencircom`
- **泄露类型**: **2 Full Leaks**
- **涉及信号**: `q` (商), `r` (余数)
- **安全幸存信号**: `a` (被除数), `b` (除数) **未泄漏** ✅

---

## 2. 漏洞发生链路分析（结合 ZKLeak 两阶段推理）

### 审计目标电路：`jose-blockchain_opencircom\test\circuits\divrem_test.circom`

该电路测试整数除法：`a = q * b + r`，其中 `a`, `b`, `q`, `r` 全部为私有输入，`quotient` 和 `remainder` 为公开输出。

```circom
    divrem.q <== q;        // 预计算的商
    divrem.r <== r;        // 预计算的余数
    quotient <== divrem.quotient;   // 公开输出
    remainder <== divrem.remainder; // 公开输出
```

### ZKLeak 推理过程（精确对应方案文档）

**阶段 I（前向信息流传播）**：
- `quotient` 信号的 $\mathcal{I}$ 中包含 `{(q, Full)}` — 商直通
- `remainder` 信号的 $\mathcal{I}$ 中包含 `{(r, Full)}` — 余直通
- `q*b` 这一乘法中间信号的 $\mathcal{I}$ 包含 `{(q, Full), (b, Full)}` — **代数盲化条件**
- `q*b + r` 的 $\mathcal{I}$ 包含 `{(q, Full), (b, Full), (r, Full)}` — **三元混合**

**阶段 II（反向约束推理）**：
- `quotient` 公开 → $\mathcal{K}(quotient) = \mathbf{FK}$
- 因 `quotient` 的 $\mathcal{I}$ 中仅有单一变量 `(q, Full)`，**不满足代数盲化条件** → $\mathcal{K}(q) = \mathbf{FK}$  ✅
- `remainder` 公开 → 同理 → $\mathcal{K}(r) = \mathbf{FK}$  ✅
- `a` 和 `b` 虽然出现在 `q*b + r` 的混合运算中，但由于乘法中间信号 $\mathcal{I}$ 包含**多个独立 Full 变量**，代数盲化检查通过，$\mathcal{K}(a) = \mathcal{K}(b) = \bot$  ✅

### 核心验证点：代数盲化安全检查
这个案例完美验证了方案文档第 II.3 节中的**代数盲化规则**：虽然 `a` 和 `b` 都参与了确定性约束 `a === q*b + r`，且 `q` 和 `r` 已知为 $\mathbf{FK}$，理论上攻击者可以通过 `a - q*b = r` 来解方程。但引擎在乘法节点 `q*b` 处检测到 $\mathcal{I}$ 中包含多个 Full 变量（`q` 和 `b`），因此**保守地不升级** `a` 和 `b`。

## 3. 审计结论：确认为有效泄露 (True Positive)
引擎精确地仅标记了 `q` 和 `r`（因直通赋值），而正确放过了 `a` 和 `b`（因代数盲化保护）。**True Positive**。
