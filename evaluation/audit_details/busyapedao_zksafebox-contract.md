# 隐私泄露审计报告：busyapedao_zksafebox-contract

## 1. 项目与漏洞概述
- **项目名**: `busyapedao_zksafebox-contract`
- **泄露类型**: **1 Full Leak (完全侧漏)**
- **涉及信号**: `in` 矩阵 (内部隐私交易数据)

---

## 2. 漏洞发生链路分析

### 审计目标电路：`busyapedao_zksafebox-contract\zk\main3.circom`

这个项目旨在构建一个“零知识避险保险箱”（Safe Box）。它拥有复杂的 `Poseidon` 哈希去遮蔽密码保护。
我们来看看它是怎么利用 `Poseidon` 保护参数的：
```circom
template Main() {
    signal input in[3];
    signal output out[4];

    poseidon1.inputs[0] <== in[0];  //psw
    out[0] <== poseidon1.out;
    
    poseidon2.inputs[0] <== in[0];  //psw
    poseidon2.inputs[1] <== in[1];  //tokenAddr
    poseidon2.inputs[2] <== in[2];  //amount

    out[1] <== in[1];
    out[2] <== in[2];
    out[3] <== poseidon2.out;
}
```

电路对 `in[0]` (密码) 采取了极其完备的哈希脱敏：它独立做了哈希，也参与了合体哈希，安全规格极高。引擎也没有对 `in[0]` 抛出任何泄漏警告。
但对 `in[1]` (代币合约地址) 与 `in[2]` (避险转移额度)，在被一起放入大熔炉（`poseidon2`）的同时，作者为了省事（或者合约需要做验证比对），直接顺手将它们的本体传给了 `out[1]` 和 `out[2]`！

因为整个 `Main()` 组件完全没有标注 Public，于是 `in[3]` 全部都是绝对隐私输入。当它把 `in` 中不可磨灭的真身映射给公共边界时，`circomspect` 的监控矩阵毫不犹豫地针对 `in` 发起了危险阻断，判定为 FULL LEAK 级泄露。

## 3. 审计结论：确认为有效泄露 (True Positive)
安全木桶效应。你用钛合金级别锁紧了密码（`in[0]`），却大开城门把资产转移对象和数量（`in[1], in[2]`）赤裸裸散落出去，让零知识沦为空谈。这是个极好的反向范例，引擎发挥正常。**True Positive**。
