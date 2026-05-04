# 隐私泄露审计报告：saharAP_phd-nova-zkml (MNIST CNN 推理)

## 1. 项目与漏洞概述
- **项目名**: `saharAP_phd-nova-zkml`（PhD 研究项目——Nova 折叠方案 + ZKML）
- **泄露类型**: **1 Full Leak (完全侧漏)**
- **涉及信号**: `argmax_out` (分类预测结果)
- **安全幸存信号**: `in[28][28][1]` (MNIST 图像输入), 所有模型权重/偏置 **均未泄漏** ✅

---

## 2. 漏洞发生链路分析

### 审计目标电路：`saharAP_phd-nova-zkml\sonobe_scheme\circuits\conv2_test.circom`

这是一个**完整的 MNIST 手写数字识别 CNN 的 Circom 实现**（186行），包含：
- `28x28x1` 灰度图像输入
- 2 层 `Conv2D` 卷积 + `BatchNormalization2D` + `ReLU` + `AveragePooling2D`
- `Flatten2D` + `Dense(200,10)` 全连接层
- `ArgMax(10)` 最终分类

这是目前审计到的**规模最大、最复杂的 ZKML 电路**。

泄漏点：
```circom
    signal input argmax_out;    // 分类结果（预期为 Public）
    signal output out;
    argmax.out <== argmax_out;  // 验证预计算的 argmax 等于实际 argmax
    out <== argmax.out;         // 输出
```

`argmax_out` 是预计算的分类结果，通过 `argmax.out <== argmax_out` 约束与实际计算的 argmax 一致，使其值等价于公开的 `out`。

与此前审计的 `wyf-ACCEPT_ZK-Decision-Tree-Demo` 形成完美呼应——后者是最简 ZKML（决策树，1 个特征），而本案是最复杂 ZKML（完整 CNN，784 像素输入 + 数千权重参数），**两者的核心泄漏模式完全一致**：模型推理结果暴露了关于输入数据的分类信息。

## 3. 审计结论：确认为有效泄露 (True Positive)
PhD 级 ZKML 研究电路中，引擎在 186 行代码、数千个信号的海量上下文中**精准锁定了 `argmax_out` 这一个泄漏点**。所有图像像素、卷积权重、BatchNorm 参数、Dense 权重等核心 ML 参数**全部安全通过**。这进一步验证了引擎在 ZKML 领域的适用性。**True Positive**。
