# 隐私泄露审计报告：costa-group_circom_tests (编译期常量分支下的泄露分析)

## 1. 项目与漏洞概述
- **项目名**: `costa-group_circom_tests`
- **涉及文件**: `correct_1` 到 `correct_9`（8个）、`not_correct_*`（8个）等
- **泄露类型**: **Full Leak (多数)** / **误报 (部分)**

---

## 2. 泄露分析：编译期常量分支的双面性

costa-group 的测试集是一组专门用于研究 Circom 编译期分支行为的学术测试电路。它的核心结构模式如下：

```circom
template Prueba(n) {
    signal input in;
    signal output out;
    var x = 0;
    
    if (n > 5) { x = 1; }        // ①编译期判定：n=7时 x=1
    
    if (x == 1) {
        out <== in;               // 直通 → Full Leak
    } else {
        out <== 0;                // 常量输出 → 无泄露
    }
}
component main = Prueba(7);       // n=7 → 走 out<==in 分支
```

### 2.1 `correct_1` (n=7)：Full Leak — **确认有效**
编译期 `n>5` 恒真，故 `x=1`，`if(x==1)` 走入 `out<==in` 分支。引擎正确识别。

### 2.2 `correct_2`：Full Leak — **误报**
```circom
if (in > 5) { x = 1; }      // ① in 是 signal，编译期 in 被解析为 0
if (y == 1) { ... }          // ② y=3 ≠ 1，恒 false → else 分支 out<==0
```
Circom 编译期对 signal 求值为 0，故 `x` 实际未被赋值为 1。但 `y==1` 恒假 → `out<==0`，输出为常量。引擎报告 Full Leak 但实际 out 是常量 0，不携带 `in` 信息。**但引擎日志同时报告了 "condition is always false" 警告**，提示开发者此分支永远不会走 `out<==in`。

### 2.3 `correct_3` (n=3)：**条件性安全**
`n==1` 为假 → `y=0` → `if(y==1)` 为假 → `out<==0`。输出恒为0，无泄露。
但引擎仍保守报告 Full Leak（因 `out<==in` 分支路径存在于 AST 中）。

### 2.4 `correct_5` (n=3)：Full Leak — **确认有效**
```circom
if (y == 1) {
    out <== in * in;
} else {
    out <== in * in;           // 两个分支完全相同！
}
```
无论走哪条分支都执行 `out=in²`，这是 Tonelli-Shanks 可逆的平方映射。Full Leak 成立。

## 3. 批量审计结论

costa-group 测试集的核心特征是**编译期常量折叠（Constant Folding）与信号作用域分离**的交叉行为：
- 当编译期参数 `n` 控制分支且走入直通路径时 → **真实 Full Leak**
- 当编译期参数使分支走入常量赋值时 → 引擎因 AST 路径分析保守性导致 **误报**
- 当两条分支结果等价时 → 无论分支选择如何都泄露 → **真实 Full Leak**

这组测试对于论文中讨论引擎的**编译期常量折叠精度极限**极具参考价值。
