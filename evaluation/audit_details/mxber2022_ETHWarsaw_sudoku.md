# 隐私泄露审计报告：mxber2022_ETHWarsaw (Sudoku)

## 1. 项目与漏洞概述
- **项目名**: `mxber2022_ETHWarsaw`
- **泄露类型**: **1 Full Leak (完全侧漏)**
- **涉及信号**: `b` (数独参数)

---

## 2. 漏洞发生链路分析

### 审计目标电路：`mxber2022_ETHWarsaw\zksnark\packages\circuit\circuits\sudoku.circom`

这个电路名义上叫"sudoku"（数独），但实际代码与数独毫无关系——它是一个迭代平方加常数的数学运算测试器：

```circom
template sudoku(n) {
    signal input a;
    signal input b;
    signal output c;

    signal int[n];
    int[0] <== a*a + b;
    for (var i=1; i<n; i++) {
        int[i] <== int[i-1]*int[i-1] + b;
    }
    c <== b;   // ← 直接等价赋值
}
component main = sudoku(1000);
```

关键泄露点超级简单：`c <== b`。虽然经历了 1000 轮的 `int[i] = int[i-1]^2 + b` 迭代运算，但最终的 output `c` 完全绕过了所有中间计算，直接等价于 `b`。

有趣的是，`a` 虽然参与了首轮 `int[0] = a*a + b` 的计算，但由于中间信号 `int[]` 并不暴露在任何 output 上，引擎**没有对 `a` 发出警告**。

## 3. 审计结论：确认为有效泄露 (True Positive)
简单的 `output <== input` 直通。引擎准确锁定 `b` 且放过了 `a`。**True Positive**。
