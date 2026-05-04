# 隐私泄露审计报告：Ty-HA_zkage-proof-mobile

## 1. 项目与漏洞概述
- **项目名**: `Ty-HA_zkage-proof-mobile`
- **泄露类型**: **2 Full Leaks (完全侧漏)**
- **涉及信号**: `userAge` (用户年龄), `minAge` (要求的最小年龄)

---

## 2. 漏洞发生链路分析

### 审计目标电路：`Ty-HA_zkage-proof-mobile\circuits\simple_age_verification.circom`

在诸多 ZK 零知识用例中，**匿名年龄认证**（只证明大于等于某岁，不透露究竟几岁）几乎是最早、最正统的招牌范例。然而这个主打手机端 ZK 年龄认证的项目，却把招牌砸得粉碎。

看看它是怎么写这个最基础的 `userAge >= minAge` 逻辑的：

#### 第一层：明文年龄的直接与间接抛出
```circom
template VerySimpleAgeVerification() {
    signal input userAge;      // Private: user's actual age  
    signal input minAge;       // Public: minimum age required
    signal output minAgeOut;   // Public: echo the minimum age
    signal output ageSquared;  // Public: userAge squared (to prove we know the age)

    // Simple constraints
    minAgeOut <== minAge;
    ageSquared <== userAge * userAge;
```
1. `minAge` 忘了在组件实例化里加 `{public [minAge]}` 声明，所以被系统默认为保护核心。但下一秒，作者直接 `minAgeOut <== minAge;` 给大喇叭全网广播了。
2. 更要命的是 `userAge`：作者为了证明“我知道这个年龄”，居然直接把它的平方给 `Output` 了（`ageSquared <== userAge * userAge;`）。因为人的年龄非常小（通常 < 150），攻击者在链上看到 `ageSquared`，直接求个开方就立刻得出了用户的精确真实年龄！

#### 第二层：画蛇添足的差值平方校验
```circom
    signal diff;
    diff <== userAge - minAge;
    signal validAge;
    validAge <== diff * diff;
```
作者认为算出差值然后再平方就万事大吉了。其实这根本不保证 `userAge >= minAge`（因为无论差值正负，平方出来都是正的）。不仅逻辑有缺陷，而且 `Circomspect` 在解析 `ageSquared` 时，其底层的代数求解器早已将其视为完全暴露（Full Leak）。

## 3. 审计结论：确认为有效泄露 (True Positive)
这个项目不仅业务逻辑出现严重谬误，还把最关键的核心隐私数据（用户年龄）通过算术平方的直接单射暴露给了 Public Output。Circomspect 准确判定这种代数关系是可以被常数级逆向解开的，认定 `userAge` 与 `minAge` 为 **FULL LEAK**。十分经典的 ZK 负面教材，**True Positive**。
