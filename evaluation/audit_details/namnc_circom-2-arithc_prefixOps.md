# 隐私泄露审计报告：namnc_circom-2-arithc (前缀算术运算符测试)

## 1. 项目与漏洞概述
- **项目名**: `namnc_circom-2-arithc` & `victoirefem_bp_final` (同源镜像)
- **泄露类型**: **3 Full Leaks (完全侧漏)**
- **涉及信号**: `a`, `b`, `c`

---

## 2. 漏洞发生链路分析与复盘

### 审计目标电路：`tests\circuits\integration\prefixOps.circom`

这两个项目似乎来源于对 Circom 编译工具链底层的算术语法进行魔改和集成测试（Integration Tests）。
在其前缀操作符（Prefix Ops）的测试用力中：

```circom
    signal input a;
    signal input b;
    signal input c;

    signal output negateA;
    signal output notA;   
    signal output complementA;
    // (同理还有 b 和 c)

    negateA <== -a;
    notA <== !a;
    complementA <== ~a;
    // ... 对 b, c 执行相同的测试
```

### ZKLeak 规则探测：
- 这是纯粹代数运算的恒等反射。
- 根据 `ccig.rs` 中的底层推理，虽然 `a` 原本不透明，但 `negateA`（等于 `-a`）作为公开输出节点被探测到处于 **FK (已知基础域要素)** 状态。
- 前置运算是一个简单的线性逆元 `-`。由于并不与其他未知私有变量混合，`a` 本身无法满足“多输入代数盲化掩蔽”，从而立刻被反向求解方程击穿。
- 布尔非 `!` 与位取反 `~` 同理，都被看做**单射的一对一确定性规则转换**。引擎不姑息这种将单一隐私输入施加固化算式后暴雪给输出管道的行为。

## 3. 审计结论：确认为有效泄露 (True Positive)
用于验证编译器前缀逻辑的 AST 遍历集，全透明的语法测例。因为所有的 `input -> output` 流转逻辑均被严格单线绑定，输入自由度为 0。**True Positive**。
