# 隐私泄露审计报告：huyphamcs_oyrade-contract-privacy (Merge2to2)

## 1. 项目与漏洞概述
- **项目名**: `huyphamcs_oyrade-contract-privacy`
- **泄露类型**: **2 Full Leaks (完全侧漏)**
- **涉及信号**: `in1Nullifier` 与 `in2Nullifier` (资产作废标识)

---

## 2. 漏洞发生链路分析

### 审计目标电路：`huyphamcs_oyrade-contract-privacy\zk\circuits\merge2to2.circom`

这个电路用于 Tornado Cash 式的资产混币网络，支持把两笔 UTXO 在零知识下合并为另外两笔金额重分配的 UTXO。
作为隐私协议的最核心部件，它的信号安全级别直接关系到协议的存亡。然而正如我们在此前审计 `withdraw.circom` 发现的那样，该项开发者并没有正确掌握约束模型。

#### 把自己的命脉交给大喇叭
```circom
template Merge2To2(depth) {
    // PUBLIC OUTPUTS
    signal output n1;
    signal output n2;

    // PRIVATE INPUT NOTE 1 (spent)
    signal input in1Nullifier;
    
    // PRIVATE INPUT NOTE 2 (spent)
    signal input in2Nullifier;

    // ... 省略大段哈希与默克尔树计算

    // --- Output nullifiers ---
    n1 <== in1Nullifier;
    n2 <== in2Nullifier;
}
```
这段代码的错误发生在一个极端矛盾的点上。由于这俩字段没有任何 public 声明白名单，所以理所当然享受全网最高规格的隐匿等级（Private）。但在此等防护下，它们直接撞上了最直白的一比一等号赋值，且接收端居然是暴露无遗的 public output：
- `n1 <== in1Nullifier`
- `n2 <== in2Nullifier`

## 3. 审计结论：确认为有效泄露 (True Positive)
和该项目下的 `withdraw` 等效，引擎完美发现变量被直接抛往公共池的危机。任何针对这个漏洞的审查者都可以通过获取 `n1` 或 `n2` 反推出用户隐藏了什么 Nullifier，进而被跨链追踪公司彻底连根拔起其所谓的 “混币” 匿名特性。确认为 **True Positive**。
