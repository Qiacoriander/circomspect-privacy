# 隐私泄露审计报告：mihirsinghal_double-blind-something

## 1. 项目与漏洞概述
- **项目名**: `mihirsinghal_double-blind-something`
- **泄露类型**: **1 Full Leak (完全侧漏)**
- **涉及信号**: `validHashes` (有效哈希白名单矩阵)

---

## 2. 漏洞发生链路分析

### 审计目标电路：`mihirsinghal_double-blind-something\poseidon_preimage.circom`

此电路实现了一个有意思的安全需求：证明你知道某个原像（preimage），这个原像的哈希值一定等于一个提供的“合法哈希白名单列表”（validHashes）中的某一项，但你不告诉外界具体是哪一项匹配。

代码逻辑是非常严丝合缝的，用连乘项 `(hasher.out - validHashes[i]) === 0` 来验证存在性：
```circom
template PoseidonPreimage(n) {
    signal input preimage;
    signal input validHashes[n];
    signal output validHashesOut[n];
    
    // 省略部分计算...

    for (var i = 0; i < n; i++) {
        differences[i] <== hasher.out - validHashes[i];
        validHashesOut[i] <== validHashes[i];  // Output the valid hashes as public signals
    }
}
```
但在白名单的输出处理中却暴雷了！
我们可以看到，`validHashes[n]` 本由于 Circom 限制没有在实例化阶段挂名 Public，于是引擎默认它们是“高度保密的内部凭证机制”。但是代码中的下一行毫不客气：`validHashesOut[i] <== validHashes[i];` 。
引擎看到：所有的矩阵元素都被无码高清、一对一等价地扔向了位于最外侧 Output 的 `validHashesOut[n]`。

## 3. 审计结论：确认为有效泄露 (True Positive)
实际上，在真正的上链验证中，`validHashes` 清单必然也是由智能合约来主导分发的（必须为公开信息），但开发者在此处显然忘记了这一点，导致工具检测到此部分私密变量被直排泄漏。这是一个强而有力的 **FULL LEAK**，归类为 **True Positive**。
