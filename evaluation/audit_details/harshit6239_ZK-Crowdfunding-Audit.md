# 隐私泄露审计报告：harshit6239_ZK-Crowdfunding-Audit

## 1. 项目与漏洞概述
- **项目名**: `harshit6239_ZK-Crowdfunding-Audit`
- **泄露类型**: **2 Full Leaks (完全泄露)**
- **涉及信号**: `total` (总筹款数), `commitments` (每个人的承诺哈希)

---

## 2. 漏洞发生链路分析

### 审计目标电路：`harshit6239_ZK-Crowdfunding-Audit\circuits\crowdfund_commit.circom`

这是一个众筹应用的零知识证明框架。作者希望能证明个人的捐款承诺和最终的总数匹配。但作者的粗心犯下了一个导致“私密捐款明文化”的惨案。

#### 真·脱裤子放屁的 Input/Output 连线
```circom
    // PUBLIC INPUTS
    signal input total;
    signal input commitments[n];

    // PUBLIC OUTPUTS
    signal output total_out;
    signal output commitments_out[n];
    
    // ...
    for (var i = 0; i < n; i++) {
        commitments_out[i] <== commitments[i];
    }
    total_out <== total;
    
// Instantiate main circuit with 4 donors
component main = CrowdfundWithCommitments(4);
```

请一定观察 `main` 的实例化：`component main = CrowdfundWithCommitments(4);`。
作者在模板内部洋洋洒洒地用注释写明了哪些是 `// PUBLIC INPUTS` 哪些是私有，然而却忘了一个至关重要的东西核心准则——Circom 的信号默认全都是私有的 (Private)，**除非在模板实例化的大括号里用 `{public [xxx]}` 声明将其涂白**。

因此：`total` 和 `commitments` 被自动作为最高机密的隐私信道对待！
但随后的代码呢？
作者生硬地通过了强相等的 `<==` 操作，把作为最高机密的 `total`，毫无保留地送进了作为必定全部上链公开的 `signal output total_out` 之内。此时隐私盾化为齑粉。

对于攻击者而言，原本他们并不知道在 ZKP 的掩护背后总共筹集到了多少钱，但由于输出端硬解码了输入端，这笔筹款账目就这么彻底地曝光在了全网的智能合约上。`circomspect` 的一层追踪系统瞬间刺穿了这个 `A = B` 的透传等式，直接发出了最高规格的 **FULL LEAK** 警告！

## 3. 审计结论：确认为有效泄露 (True Positive)
这是一次标准的由于代码编写者未能深刻理解零知识引擎中的 Public 参数宣告范式而引发的血崩。用错误的语法构建伪安全屏障最终导致底层状态直接发送上链。系统一发入魂，捕获完美，属于真实的 **True Positive**。
