# 隐私泄露审计报告：Pecunia-Labs_pecunia-tron (ZK保险箱)

## 1. 项目与漏洞概述
- **项目名**: `Pecunia-Labs_pecunia-tron`
- **泄露类型**: **1 Full Leak (完全侧漏)**
- **涉及信号**: `in[1]` (代币地址) 和 `in[2]` (金额)

---

## 2. 漏洞发生链路分析

### 审计目标电路：`Pecunia-Labs_pecunia-tron\backend\zk\circuit3\main3.circom`

该电路与此前审计的 `busyapedao_zksafebox-contract\zk\main3.circom` **完全同源**（license 头、代码结构、变量命名一字不差），是同一份 Poseidon 保险箱模板代码在不同项目中的复用。

```circom
    poseidon1.inputs[0] <== in[0];  //psw  → 哈希保护 ✅
    out[0] <== poseidon1.out;

    poseidon2.inputs[0] <== in[0];  //psw
    poseidon2.inputs[1] <== in[1];  //tokenAddr
    poseidon2.inputs[2] <== in[2];  //amount
    out[1] <== in[1];               // ← 明文直通 ❌
    out[2] <== in[2];               // ← 明文直通 ❌
    out[3] <== poseidon2.out;
```

与 zksafebox 完全相同的木桶效应：密码 `in[0]` 被 Poseidon 双重保护，但代币地址和转移金额直接裸露。

## 3. 审计结论：确认为有效泄露 (True Positive)
与 busyapedao_zksafebox 同源代码，同一缺陷在不同项目间传播，进一步验证了引擎的一致性。**True Positive**。
