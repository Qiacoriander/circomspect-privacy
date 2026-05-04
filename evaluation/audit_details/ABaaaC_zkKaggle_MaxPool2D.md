# 隐私泄露审计报告：ABaaaC_zkKaggle (2D最大池化运算)

## 1. 项目与漏洞概述
- **项目名**: `ABaaaC_zkKaggle`
- **泄露类型**: **1 Full Leak (完全侧漏)**
- **涉及信号**: `in` (输入的 2D 张量特征图)

---

## 2. 漏洞发生链路分析与复盘

### 审计目标电路：`ABaaaC_zkKaggle\test\circuits\MaxPool2D_test.circom`

这个项目是构建用于机器学习模型在链上运行的 ZKML 算子。
在测试他们自定义的最大池化(`MaxPool2D`)操作时，其测试脚本搭建了一个如下的环境：

```circom
template maxpool2d_test(kernel_size) {
    signal input in[kernel_size][kernel_size];
    signal output out;

    component maxpool = MaxPool2D(kernel_size);
    for (var i = 0; i < kernel_size; i++) {
        for (var j = 0; j < kernel_size; j++) {
            maxpool.in[i][j] <== in[i][j];
        }
    }
    out <== maxpool.out;
}
```

### ZKML 中典型的高风险场景：
这段代码实际上暴露出机器学习 ZKP 中极为常见的一个反模式问题：
`MaxPool2D` 的本质是从一个局部的感知野（例如 2x2 或 3x3 的信号矩阵）中，通过不断的数值比较，挑选出**最大值**作为输出。
这意味着 `out` 必定**严格等价于** `in` 矩阵中某一个特定索引处的原始特征值。

虽然这个操作具备非线性特性（类似 Hash 降维，因为它丢弃了其他较小像素），并且经过了比较门的条件选择（由底层 `LessThan` 等原语驱动，引擎抛出了多个 Partial Leak 断点），但是对于被选中的**那个**像素点而言，它的**绝对真值**被一字不漏地传导给了 `out`（它没有经历乘法加法掩盖，也不是输出的范围，而是像素原文）。引擎在阶段二捕获了这条透明传导链。

## 3. 审计结论：确认为有效泄露 (True Positive)
这是有效测试，它提醒审核者：类似于 `MaxPool` 或 `ReLU` (当激活时) 等激活/汇聚操作，如果不经过后续网络层哈希或者加权聚合，而是像测试环境里这般**直接**吐给公共总线，那么特征图的原始敏感信息将被无损切片广播，构成严重的完全暴露（Full Leak）。**True Positive**。
