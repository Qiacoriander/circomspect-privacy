# 隐私泄露审计报告：CaptainLEVI-XXX_zk2FA (零知识双因子认证)

## 1. 项目与漏洞概述
- **项目名**: `CaptainLEVI-XXX_zk2FA`
- **泄露类型**: **1 Full Leak (完全侧漏)**
- **涉及信号**: `hash` (预期的认证哈希)
- **安全幸存信号**: `pass` (密码) 和 `addr` (地址) **均未泄漏** ✅

---

## 2. 漏洞发生链路分析

### 审计目标电路：`CaptainLEVI-XXX_zk2FA\circuit\HashCheck\hashCheck.circom`

这是一个**零知识双因子认证（2FA）**系统。设计思路是：用户输入密码 `pass` 和地址 `addr`，电路用 Poseidon 哈希计算出结果，验证其与预期的 `hash` 一致。

```circom
template Main() {
    signal input pass;   // 密码（Private）
    signal input addr;   // 地址（Private）
    signal input hash;   // 预期哈希（注释没说，默认Private）

    signal output out;

    component h = Poseidon(2);
    h.inputs[0] <== addr;
    h.inputs[1] <== pass;
    out <== h.out;
    out === hash;    // 验证一致性
}
component main = Main();  // 没有 {public [hash]}
```

`hash` 应当是链上公开存储的验证凭据（类似传统2FA中的"服务器端存储的哈希"），但遗漏了 `{public [hash]}` 声明。由于 `out === hash` 使 `hash` 与公开输出 `out` 完全等价，引擎判定其为 Full Leak。

核心亮点：`pass` 和 `addr` 经过 Poseidon 单向哈希保护，引擎**没有对其发出任何告警**。

## 3. 审计结论：确认为有效泄露 (True Positive)
白名单语法遗漏导致的告警。在实际部署中 `hash` 的确是公共知识（存储在合约中供比对），但引擎的标识完全正确。**True Positive**。
