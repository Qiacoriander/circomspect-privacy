# 隐私泄露审计报告：mxber2022_ETHWarsaw

## 1. 项目与漏洞概述
- **项目名**: `mxber2022_ETHWarsaw`
- **泄露类型**: **2 条风险（1 Full + 1 Partial）**
- **涉及信号**: `nullifier` (防双花防重放字段) 

## 1.1 本轮复核更新（2026-03-22）
- 检测计数由 `2(2/0)` 调整为 `2(1/1)`
- `nullifier` 直通导致的核心 Full 风险仍保留，另一条告警降级为 Partial

---

## 2. 漏洞发生链路分析

### 审计目标电路：`mxber2022_ETHWarsaw\zksnark\packages\mycircuit\feedback.circom`

这个电路似乎是 2022 年 ETHWarsaw Hackathon 的项目。其设计目标是让用户可以匿名提交 Feedback，同时使用 Nullifier（作废符）来防止双重提交。

#### 最典型的 Private-to-Public 明文透传
我们来看看它是如何处理 Nullifier 的：
```circom
template FeedbackCircuit() {
    // Inputs (未声明 Public，所以默认全是 Private)
    signal input userPublicKey; // User's wallet address (private by default)
    signal input feedbackHash;  // Feedback hash (public)
    signal input nullifier;     // Nullifier to prevent double submissions (public)

    signal output nullifierOutput;

    // Directly use the nullifier as the output
    nullifierOutput <== nullifier;
}
```
作者在注释里自己写了 `// Nullifier ... (public)`，但由于对于 Circom 语法不够了解，他**并没有在主实例化组件中声明 `{public [nullifier]}`**。
其结果是引擎将其分配为了绝对隐私级数据。但随后的一句 `nullifierOutput <== nullifier;` 则将这个隐私数据一字不落地广播到了链上的公开输出中。

## 3. 审计结论：确认为有效泄露 (True Positive)
虽然作者的“本意”是将其设为白名单 Public 变量，且这种透传如果写了白名单就是正常的业务表现。但由于语法书写的遗漏，此时该项目等价于“在非自愿/未授权状态下，强制把隐私数据发送至公有端”，这种范式如果发生在真正核心的私有数据上将会导致底裤被看穿。
`circomspect` 精确捕捉到了该直通管道 (Identity Mapping)，上报了 **FULL LEAK**。确认为 **True Positive**。
