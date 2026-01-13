# 函数调用盲区 (Function Call Blindness)

## 问题描述
`circomspect` 的量化分析在早期版本中主要针对 `template` 层级的控制流图（CFG）进行。当遇到 `function` 调用时，分析器采取黑盒策略，无法深入分析函数内部的具体操作。因此，定义在纯函数（Function）体内部的直接位操作（如 `>>`, `&`）对于量化分析器是不可见的。

## 当前状态：[已解决]

**解决程度**：
- **完全支持**：已在 `privacy_taint` 分析 pass 中实现了针对 Function CFG 的递归分析机制。
- **实现原理**：
    1. **即时分析 (On-the-fly Analysis)**：当分析器遇到 `Call` 表达式指向一个 Function 时，会创建一个新的临时分析环境。
    2. **上下文映射**：将调用处的参数污点等级（Taint Level）映射到函数的形参。
    3. **内部传播**：在函数体内部运行简化版的污点传播和泄露跟踪。
    4. **泄露回溯**：如果函数参数在内部发生了位泄露（如 `(param >> i) & 1`），该泄露量会被捕获并回溯累加到调用处对应的实参（Argument）上。
    5. **返回值传播**：函数的返回值污点等级会被计算并返回给调用表达式。
    6. **性能优化 (Memoization)**：引入全局函数缓存 `function_cache` (类型为 `Rc<RefCell<HashMap>>`)。
        *   在分析任何函数前，先检查 `(Function Name, Arguments Taint Levels)` 是否已在缓存中。
        *   如果是，直接返回缓存的 `(Return Taint, Leakage Map)`，跳过重复计算。
        *   这极大地优化了包含大量重复函数调用（如大数运算库）的电路分析性能，避免了指数级的时间复杂度。

## 验证方法
运行本目录下的 `main.circom`：
```circom
// main.circom 定义了一个 function extractBit(x) { return (x >> 10) & 1; }
// Main 组件调用此函数： out <== extractBit(in);
// 预期结果：Main 的输入 `in` 应当被报告存在 1 比特的量化泄露 (CS0021)。
```

**运行命令**:
```bash
cd d:\dev\circomspect
cargo run --release -- benchmarks/test_cases/limitations/test_function_blindness/main.circom --mode main --leak-threshold 1 --min-leak-severity Low
```

**预期输出**:
应包含如下警告，表明分析器成功穿透了函数调用：
```text
warning[CS0021]: Private signal `in` has quantified information leakage (Severity: Low, L(x)=1 bits, ...)
```

### 进阶验证：复杂场景 (Deep Recursion & Aggregation)
我们补充了 `complex_recursion.circom` 测试用例，验证以下复杂场景的支持情况：

1.  **多层递归与聚合 (Nested Aggregation)**:
    *   场景: `Main` -> `leakTwoBits` -> 调用 `leakBit0` (泄露1位) 和 `leakBit1` (泄露1位)。
    *   结果: 正确报告输入信号泄露 **2 bits**。证明分析器能够正确递归分析并累加子函数的泄露量。

2.  **多次不同调用 (Multiple Calls)**:
    *   场景: `Main` 调用 `leakBit0(in)` + `leakBit1(in)`。
    *   结果: 正确报告 **2 bits** 泄露。证明不同函数的泄露操作能够被正确累加。

3.  **重复调用去重 (Deduplication)**:
    *   场景: `Main` 调用 `leakBit0(in)` + `leakBit0(in)`。
    *   结果: 正确报告 **1 bit** 泄露。证明对同一处泄露源的重复调用会自动去重，避免过度误报。

**运行复杂测试命令**:
```bash
cargo run --release -- benchmarks/test_cases/limitations/test_function_blindness/complex_recursion.circom --mode main --leak-threshold 1 --min-leak-severity Low
```

