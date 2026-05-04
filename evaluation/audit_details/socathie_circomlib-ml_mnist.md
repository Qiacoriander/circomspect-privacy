# 隐私泄露审计报告：socathie_circomlib-ml (MNIST CNN推理 186行 / 2800+信号)

## 1. 项目与漏洞概述
- **项目名**: `socathie_circomlib-ml` — 首个社区级 ZK-ML Circom 库
- **电路文件**: `test/circuits/mnist_test.circom` (186行，~2800信号)
- **泄露类型**: **1 Full Leak**
- **涉及信号**: `argmax_out` (分类结果预输入值)
- **关联文件**: `model1_test.circom` — `Dense21out` Full Leak

---

## 2. 电路架构分析

这是一个**完整的 MNIST 手写数字识别 CNN 推理电路**，管线包含：

```
in[28][28][1]  →  Conv2D(3×3, 1→4)  →  BatchNorm2D  →  ReLU  →  AvgPool2D(2×2)
             →  Conv2D(3×3, 4→8)  →  BatchNorm2D  →  ReLU  →  AvgPool2D(2×2)  
             →  Flatten2D(5×5×8=200)  →  Dense(200→10)  →  ArgMax(10)  →  out
```

### 关键设计特征：中间结果作为私有输入
该电路采用**"预计算 + 约束验证"** 范式：每一层的中间输出（如 `conv2d_1_out[26][26][4]`）和余数（如 `conv2d_1_remainder[26][26][4]`）都作为**私有输入**传入，电路本质上只在验证这些中间结果的一致性（而非从头计算）。这是 ZKML 的常见设计：
- `out[i][j][k]`：该层的预计算输出
- `remainder[i][j][k]`：整数除法的余数（用于定点量化对齐）

## 3. 泄露分析

### 3.1 Phase 1 日志详析（134行 DEBUG）
引擎扫描了约2800个信号节点，产生134行Phase 1调试输出。**令人印象深刻的是，所有 Mul/AddSub/Select/BitExtract 操作的污点输出均为空 `{}`**：

```
DEBUG: Phase 1 output for sig_id 161 from op_id 160 (type: Mul): {}
DEBUG: Phase 1 output for sig_id 317 from op_id 316 (type: Mul): {}
... (120+ 行全为 {})
```

这意味着所有 Conv2D、Dense、BatchNorm 层的乘加操作中的私有权重、偏置、中间激活值均**相互掩蔽**，不会泄露到输出端。引擎对多变量代数盲化的识别在此2800+信号的大规模电路中完美运作。

### 3.2 唯一泄露点：`argmax_out`
```circom
signal input argmax_out;         // 私有输入
signal output out;                // 公开输出
// ...
argmax.out <== argmax_out;       // 约束验证
out <== argmax.out;              // 直通输出
```

`argmax_out` 是 ArgMax(10) 组件的预计算输出，被约束等于 `argmax.out` 后直接赋给公开输出 `out`。这构成一条确定性链路：
- Phase 1: `argmax_out` → (约束等价) → `argmax.out` → (赋值) → `out`
- Phase 2: 反向推理 K(out)=FK → K(argmax_out)=FK

### 3.3 `argmax_out` 泄露的语义讨论
从ZKML协议设计角度看，**分类结果本身就是需要公开的信息**——verifier需要知道模型输出了什么分类。这个 "Full Leak" 在设计语义上是 **intentional（有意的）**：
- `argmax_out` 代表"模型认为输入图片是数字几"
- 这正是ZK推理证明要向verifier公开的信息
- 隐私保护目标是隐藏**输入图片 `in[28][28][1]`** 和**模型权重**，而非分类结果

因此，更准确的做法是将 `argmax_out` 改为 `component main { public [argmax_out] }` 显式声明为公开输入，消除警告。

### 3.4 model1_test 的关联泄露
```
warning: Private Input `Dense21out` has a FULL LEAK risk
```
`Dense21out[1]` 是最后一层 Dense(2→1) 的预计算输出——同样语义上应公开。引擎额外发现 `Dense21bias[1]` 和 `Dense32bias[2]` 为未使用信号。

## 4. 审计结论
- **argmax_out / Dense21out**: 确认为有效泄露 (True Positive)，但属于 **语义优先级低** 的泄露——分类结果本身就是设计上需要公开的信息，只是缺少 `{ public [...] }` 声明。
- **in[28][28][1] / weights / bias**: 无泄露 — 2800+信号中引擎零误报地识别了多变量代数盲化
- **论文价值**: 作为 circomlib-ml 开创性标杆项目的186行CNN电路，是引擎**大规模回路可扩展性（Scalability）**的极佳实证。
