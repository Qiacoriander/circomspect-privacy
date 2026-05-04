# 隐私泄露审计报告：agnij-dutta_sigil (领导力凭证)

## 1. 项目与漏洞概述
- **项目名**: `agnij-dutta_sigil`
- **泄露类型**: **1 Full Leak (完全侧漏)**
- **涉及信号**: `yearsOfLeadership` (领导力经验年数)

---

## 2. 漏洞发生链路分析

### 审计目标电路：`agnij-dutta_sigil\web3\circuits\credentials\leadership_credential.circom`

Sigil 凭证系统的**第四个审计电路**——用于证明用户具备足够年限的领导力经验。

日志中 329 行的海量 DEBUG 信息（主要是 Compare 和 LogicGate）说明这是一个高度复杂的多层级验证电路。然而最终引擎只输出了 1 个警告：`yearsOfLeadership` 为 Full Leak。

从 DEBUG 信息的传播模式可以看到：`yearsOfLeadership` (sig_id 53/83) 经过了 `Mul`、`AddSub` 等运算后，其 Full 标签被传播到了输出端。与之前的 Partial Leak 案例（collaboration、language）不同——此次的领导力年数通过确定性约束被完全推导出来。

## 3. 审计结论：确认为有效泄露 (True Positive)
Sigil 凭证系统至此已审计 4 个电路：3 个 Partial + 1 个 Full。这个 Full Leak 打破了此前的模式——说明该系统的某些凭证比其他凭证存在更严重的隐私缺陷。**True Positive**。
