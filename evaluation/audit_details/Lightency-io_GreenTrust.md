# 隐私泄露审计报告：Lightency-io_GreenTrust

## 1. 项目与漏洞概述
- **项目名**: `Lightency-io_GreenTrust`
- **泄露类型**: **1 Full Leak + 1 Partial Leak**
- **涉及信号**: `a` (Full Leak), `b` (Partial Leak)

---

## 2. 漏洞发生链路分析

### 审计目标电路：`Lightency-io_GreenTrust\ZKP\equal.circom`

GreenTrust 项目看起来是一个**绿色能源可信认证平台**，使用 ZKP 来验证能源数据的合规性。此电路用于证明两个值相等，而不外泄它们的值。

但代码实现完全违背了这个设计初衷：

```circom
template EqualCheck() {
    signal input a;
    signal input b;
    signal output result;
    signal output publicA;

    component isEqual = IsEqual();
    isEqual.in[0] <== a;
    isEqual.in[1] <== b;

    result <== isEqual.out;
    publicA <== a;    // ← 直接把 a 送出去了！
}
```

#### Full Leak: `a` 的完全暴露
`publicA <== a;` 这一行将本该加密保护的私有能源测量值 `a` 未加任何处理直接发送到了公共输出。引擎准确判定为 Full Leak。

#### Partial Leak: `b` 的部分泄露
`result <== isEqual.out;` 将比较结果（0 或 1）公开。由于 `a` 已经是 Full Leak（公开了），而 `result` 告诉攻击者 `a == b` 是否成立，所以攻击者可以直接推断 `b` 的值：
- 若 `result == 1`，则 `b == a`（完全暴露）
- 若 `result == 0`，则 `b != a`（仅排除一个值）

引擎将其保守地标记为 Partial Leak，这是正确的（因为在 `result == 0` 时确实无法确定精确值）。

## 3. 审计结论：确认为有效泄露 (True Positive)
作为绿色能源合规认证的核心密码模块，直接把待验证值明文广播出去，完全丧失了零知识特性。引擎对两种不同程度泄漏的分层标记也体现了高精度区分能力。**True Positive**。
