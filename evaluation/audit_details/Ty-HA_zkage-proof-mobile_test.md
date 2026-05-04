# 隐私泄露审计报告：Ty-HA_zkage-proof-mobile (年龄验证测试代码)

## 1. 项目与漏洞概述
- **项目名**: `Ty-HA_zkage-proof-mobile`
- **泄露类型**: **2 Full Leaks (完全侧漏)**
- **涉及信号**: `userAge` (私密真实年龄), `minAge` (公开要求底线年龄)

---

## 2. 漏洞发生链路分析与复盘

### 审计目标电路：`Ty-HA_zkage-proof-mobile\circuits\test_age_verification.circom`

这个来自移动端零知识年龄验证系统原型的开发者测试（Testing）文件，犯了可以说是最经典的 **"测试代码直接裸奔"** 错误。

```circom
template TestAgeVerification() {
    signal input userAge;      // Private: user's actual age
    signal input minAge;       // Public: minimum age required
    signal output out1;        // Public: first output
    signal output out2;        // Public: second output

    // Very simple logic for testing
    out1 <== minAge;           // First public signal = minAge
    out2 <== userAge;          // Second public signal = userAge
    // ...
}
```

按照 ZK 的安全铁律，**任何形式的输入只要从 `main` 模板中被指定为 `output` 级别，就必然会通过零知识证明关联并最终向全网矿工和验证节点广播真值明文**。
虽然注释中专门以 "// Private:" 给 `userAge` 做了标记，开发者在设计专门的 `test_` 测试模块验证逻辑完备性时，为了快速校验计算和追踪流向，把本来应当只在后台隐匿验算的参数直通给了 Public Output 数组中的 `out2`。

这种“在研发期测试脚手架中强行向外打印看结果”的代码，如果被误编入生产包上链发布，其零知识承诺将直接变成明文记账本。

## 3. 审计结论：确认为有效泄露 (True Positive)
极其明朗的双线完全泄密（Full Leak），属于开发/调试阶段的工程性遗留风险。引擎在第一时间顺着控制流 AST 发现私有输入与公共输出节点的关联绑定。**True Positive**。
