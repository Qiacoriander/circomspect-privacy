# 隐私泄露审计报告：Pecunia-Labs_pecunia-tron (简化版保险箱)

## 1. 项目与漏洞概述
- **项目名**: `Pecunia-Labs_pecunia-tron`
- **泄露类型**: **1 Full Leak (完全侧漏)**
- **涉及信号**: `in[1]` (转账金额)
- **安全幸存信号**: `in[0]` (密码) 经 Poseidon **未泄漏** ✅

---

## 2. 漏洞发生链路分析

### 审计目标电路：`Pecunia-Labs_pecunia-tron\backend\zk\new_circuit\circuit.circom`

这是同一项目下 `main3.circom` 的**简化版本**——从 3 参数（密码+代币地址+金额）缩减到了 2 参数（密码+金额）：

```circom
template Main() {
    signal input in[2];     // in[0]=密码, in[1]=金额
    signal output out[3];

    poseidon1.inputs[0] <== in[0];  //psw → 哈希 ✅
    out[0] <== poseidon1.out;

    poseidon2.inputs[0] <== in[0];  //psw
    poseidon2.inputs[1] <== in[1];  //amount
    out[1] <== in[1];               // ← 金额明文直通 ❌
    out[2] <== poseidon2.out;
}
```

与 `main3` 同模式：密码安全，金额裸露。

## 3. 审计结论：确认为有效泄露 (True Positive)
Pecunia-Tron 项目下两个电路（main3 和 circuit）均存在同一模式的 Full Leak。**True Positive**。
