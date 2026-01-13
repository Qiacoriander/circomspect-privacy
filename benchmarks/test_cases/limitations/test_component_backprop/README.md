# 组件间泄露不回溯 (Transitive Back-propagation)

## 问题描述
在早期的 Circomspect 版本中，程序分析是**模块化**（Intra-procedural）的。这意味着每个 `template` 被独立分析。当父组件将私有输入连接到子组件时，即使子组件内部存在明确的位提取操作（导致部分信息泄露），这个泄露信息也**不会反向传播**给父组件的输入信号。这导致调用者无法感知到底层组件带来的隐私风险。

## 当前状态：[已解决]

**解决程度**：
- **完全支持**：Circomspect 现在的隐私污点分析（Privacy Taint Analysis）实现了跨组件的泄露回溯机制。
    - **递归分析**：CLI 工具现在会构建完整的控制流图（CFG）链接，并在分析 `main` 或顶层组件时，递归地进入子组件进行分析。
    - **泄露回溯**：当子组件的输入端口检测到量化泄露（Quantified Leakage, CS0021）时，该信息会通过连接关系反向传播给父组件的对应信号。
    - **库组件支持**：对于标准库组件（如 `Num2Bits`），内置了特定的泄露规则，无需深入递归即可快速回溯泄露属性。

## 验证方法
运行本目录下的 `main.circom`：
```circom
// main.circom 包含一个名为 SubLeaker 的子组件，它对输入进行位提取。
// Main 组件将私有输入 secret 连接到 SubLeaker。
// 预期结果：Main 的输入 secret 应当报告 CS0021 (Quantified information leakage)。
```

**运行命令**:
```bash
cd d:\dev\circomspect
// 确保使用 --mode main 启用递归分析
cargo run --release -- benchmarks/test_cases/limitations/test_component_backprop/main.circom --mode main --leak-threshold 1 --min-leak-severity Low
```

**预期输出**:
应包含类似以下的警告：
```text
warning: Private signal `secret` has quantified information leakage ...
```
这表明泄露成功从 `SubLeaker` 回溯到了 `Main` 的 `secret` 信号。
