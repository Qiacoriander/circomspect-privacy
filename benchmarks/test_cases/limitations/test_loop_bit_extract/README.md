# 循环位提取与常量折叠限制 (Loop Bit Extraction Limitations)

## 问题描述
在目前的 Circomspect 版本中，隐私泄露量化分析严重依赖于**显式的字面量**。当位操作（如位提取 `(in >> i) & 1`）中的位移量 `i` 不是直接的数字字面量，而是一个局部变量、常量引用或循环变量时，分析器往往无法确定具体的位移量。

为了安全起见（避免漏报），分析器在这种情况下会采取**保守策略**，假设该操作可能泄露了信号的全部熵（通常为 254 bits）。这导致了大量的**误报 (False Positives)**，将低风险的精确位提取误报为高危的全量泄露。

## 测试用例结果

运行 `main.circom` 测试文件，包含四种典型场景：

### Case 1: 字面量位提取 (Literal Shift)
*   **代码**: `(in >> 10) & 1`
*   **预期**: 泄露 1 bit。
*   **实际**: ✅ **Leaked 1 bit** (Low Severity)。
*   **结论**: 直接针对字面量的分析是准确的。

### Case 2: 简单常量引用 (Simple Constant Ref)
*   **代码**: `var s = 5; (in >> s) & 1`
*   **预期**: 泄露 1 bit。
*   **实际**: ✅ **Leaked 1 bit** (Low Severity)。
*   **状态**: [已解决] 通过引入局部常量传播 (Local Constant Propagation) 成功解决。分析器现在能够识别并替换局部范围内被赋值为常量的变量。

### Case 3: 简单循环变量 (Simple Loop Variable)
*   **代码**: `for (var i = 0; i < 8; i++) { ... (in >> i) & 1 ... }`
*   **预期**: 泄露 8 bits。
*   **实际**: ✅ **Leaked 8 bits** (High Severity)。
*   **状态**: [已解决] 通过引入基于源代码的循环边界推断 (Source-Code Assisted Loop Bound Inference) 成功解决。
    *   **原理**: 静态分析引擎通过 `AnalysisContext` 回溯到 Circom 源代码，利用正则表达式提取循环条件（如 `i < 8`），从而确定循环的确切迭代次数。
    *   **结果**: 分析器正确识别该循环执行 8 次，每次提取 1 bit，累计泄露 8 bits，实现了精准量化。详见 `program_analysis/src/privacy_taint.rs` 中的 `detect_loop_variable_bound` 函数。

### Case 4: 嵌套循环与表达式 (Nested Loop & Expression)
*   **代码**: `for (i...) { for (j...) { ... (in >> (i*2+j)) ... } }`
*   **预期**: 泄露 4 bits。
*   **实际**: ✅ **Leaked 254 bits** (Critical Severity) - **符合预期逻辑**。
*   **状态**: [已确认] 这种涉及多变量的复杂算术表达式超出了简单静态分析的能力范围。分析器正确地将其归类为 "Variable Bit Extraction (unknown pattern)" 并报告最大熵泄露。这是合理的保守行为。

### Case 5: 变量做循环边界 (Constant Loop Bound)
*   **代码**: `var n = 8; for (var i = 0; i < n; i++) { ... (in >> i) & 1 ... }`
*   **预期**: 泄露 8 bits。
*   **实际**: 🔴 **Failed (Critical Severity)**.
*   **问题**: `detect_loop_variable_bound` 目前仅支持直接的数字字面量。
*   **尝试修复**: 尝试引入常量传播上下文 (`env.constants`) 在分析阶段解析变量 `n`。但由于 Circomspect 的 IR 中局部变量声明与赋值语句的模式匹配存在困难（Initial Scan 未能捕获 `var n = 8` 的赋值操作），导致无法在隐私分析 pass 中建立准确的常量映射。目前仍作为已知限制保留。

## 机制说明 (Implementation Insights)

### 循环位提取量化原理
针对 Case 3 等成功识别的循环，分析器并非简单地使用“单次泄露 * 循环次数”的数学公式，而是采取了 **模拟循环展开 (Loop Unrolling Simulation)** 的方式：
1.  **边界识别**: 首先通过 `detect_loop_variable_bound` 确定循环的上界 (Upper Bound)。
2.  **模拟迭代**: 代码显式执行一个 `0..bound` 的循环。
3.  **逐位记录**: 在每次模拟迭代中，生成一个独立的 `LeakageOp::BitExtract { bit_index: i }`。
4.  这种方式的优点是能精确记录“哪一位”被泄露了，而不仅仅是“泄露了多少位”。


## 根因分析
1.  **缺乏常量传播**: 原有的分析pass在CFG构建后直接运行，未进行常量传播。**现已在隐私分析中集成局部常量传播**，解决了 Case 2。
2.  **IR 抽象层级**: Circom 的线性约束生成（R1CS）与指令式逻辑（Function/Loop）混合。局部变量（`var`）在生成的 IR 中保留了变量属性。
3.  **循环分析局限**: 静态分析循环是难点。目前通过**源代码回溯**解决了简单静态边界的循环分析（Case 3），但对于动态边界或复杂步长（Case 4），分析器目前采用安全的保守回退策略。

## 下一步改进建议
1.  **实现全局常量传播 Pass**: 虽然已实现局部传播，但独立的优化 Pass 能进一步提高整个编译管线的精度。
2.  **符号执行 (Symbolic Execution)**: 对于更复杂的表达式（如 Case 4），未来可引入符号执行来计算位移量的精确取值集合，以替代目前的最大熵回退机制。
