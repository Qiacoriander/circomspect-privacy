# 审计报告：Teycir_ZkPatternFuzz

## 概述
- **项目名**: `Teycir_ZkPatternFuzz`
- **文件路径**: `Teycir_ZkPatternFuzz\tests\ground_truth\chains\mode123_smoke\mode123_chain_step0.circom`
- **泄露类型**: 有效级联泄露 (True Positive Cascade Leak)

## 电路源码分析
核心相关代码如下：
```circom
template Mode123ChainStep0() {
    signal input a;
    signal input b;
    signal output sum;
    signal output rhs;

    sum <== a + b;
    rhs <== b;
}
```

## 审计过程与机制解释
在上述电路中，有两个私有输入 `a` 和 `b`，以及两个公开输出 `sum` 和 `rhs`.
1. **直接泄露 (Direct Leak)**：公开输出 `rhs` 直接被赋值为 `b`。攻击者通过观察 `rhs` 的值，就能完全推断出私有输入 `b` 的确切值（即 `b` 为 Fully Known）。
2. **级联泄露 (Cascade Leak / Relational De-blinding)**：公开输出 `sum` 被限制为 `a + b`。在正常的盲化假设下，如果 `b` 未知，`sum` 只能算作对 `a` 的一个掩蔽（被 `b` 盲化了）。但是，由于 `b` 已经在前一步被完全泄露（变成 Fully Known），盲化因子失效。系统进入第二阶段的后向推断（Phase II backward inference），触发了“代数解盲连锁突围（Relational De-blinding）”规则。因为 `sum` 和 `b` 皆为已知，攻击者可以轻易通过 `a = sum - b` 求解出 `a`，最终导致 `a` 也发生 **FULL LEAK**。

## 结论
**审计状态：确认为有效泄露**。
该案例完美展示了 `circomspect` 中代数解盲（Relational De-blinding）和级联泄露追踪（Cascade Leak Tracking）的能力，是一个非常典型的有效泄露例子。
