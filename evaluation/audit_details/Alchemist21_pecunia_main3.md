# 隐私泄露审计报告：Alchemist21_pecunia (保险箱转账凭据)

## 1. 项目与漏洞概述
- **项目名**: `Alchemist21_pecunia`
- **泄露类型**: **1 Full Leak (完全侧漏)**
- **涉及信号**: `in[3]` (密码、代币凭证、转账额度)

---

## 2. 漏洞发生链路分析与复盘

### 审计目标电路：`Alchemist21_pecunia\zk\circuit3\main3.circom`

这个项目构建了一个需要密码（保险箱解密）才能完成代币定向划转的 ZK 电路。与我们之前审计到的 `busyapedao_zksafebox-contract` 所犯的结构性大漏洞一模一样！

```circom
template Main() {
    signal input in[3];   // <- 私有数组
    signal output out[4]; // <- 公开源组

    // ...
    poseidon2.inputs[0] <== in[0];  //psw 密码进 Poseidon 掩模脱敏
    poseidon2.inputs[1] <== in[1];  //tokenAddr
    poseidon2.inputs[2] <== in[2];  //amount
    
    // 致命赋值：
    out[1] <== in[1];        // tokenAddr 明文全裸广播
    out[2] <== in[2];        // amount 明文全裸广播
    out[3] <== poseidon2.out;
}
```

### 流向追踪：致命的漏配白名单
核心意图本是提供一套包含 `tokenAddr` 加 `amount` 和 `passwrod` 在内的零知识认证，确保调用者能够执行提单。
代码利用了 `Poseidon(3)` 包装全部信息，这本是优秀的习惯。但它未配置合规的 `signal input public [...]` 白名单！开发者只能把本该作为前置公开条件的金额和地址通过暗箱输入管道一起塞进去了，因为外部矿工也需要验真这些标量！随后在电路结尾，开发者用硬赋值 `<==` 把它们强行提取出来抛回全网验证人。隐私数组的 `in` 由于部分元素直出而惨遭击破！

## 3. 审计结论：确认为有效泄露 (True Positive)
经典“以暴露私有变量掩饰遗漏公开配置”的大坑。金额及目标地址（作为敏感因素）被等值直接推上公共天线下发。**True Positive**。
