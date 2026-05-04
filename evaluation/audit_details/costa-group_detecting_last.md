# 隐私泄露审计报告：costa-group_circom_tests（检测最后赋值路径下的泄露分析）

## 1. 项目与漏洞概述

- **项目名**: `costa-group_circom_tests`
- **涉及文件夹**: `detecting_last_assignment/`（5 个电路）
- **泄露类型**: **Full Leak（全部 5 个）**

本组测试集专门用于研究 ZKLeak 引擎在**多模板组合 + 条件/循环赋值路径**下识别"最后一次有效赋值"的能力。核心问题：当某个信号在多条路径（条件分支 / 循环 / 直接赋值）中被多次赋值时，引擎能否正确追踪 Phase 1 污点并在 Phase 2 确认 Full Leak。

---

## 2. 公共基础结构

所有 5 个文件均共用如下两个子模板：

```circom
template C() {
    signal input in;
    signal output out;
    out <== in * in;          // C: out = in²
}

template B() / B(n) {
    signal input in1 [, in2];
    signal output out;
    out <== in1 * in2;        // B: out = in1 × in2
}
```

主模板 `A` 通过不同方式给 `a.in1` 和 `a.in2` 赋值，最终 `out <== a.out`。

---

## 3. 各案例分析

### 3.1 `known_last_assignment_1_signal_comp`（L113，最简版）

```circom
template A() {
    signal input in;
    signal output out;
    component a = B();
    component a1 = C();
    a1.in <== in;
    a.in1 <== a1.out;    // in²，<== 约束
    a.in2 <== a1.out;    // in²，<== 约束
    out <== a.out;       // = in² × in² = in⁴
}
```

**约束链**：`out = in⁴`  
**Phase 1**：
- `C`: Mul(`in`,`in`) → `{(in, Full)}`（单变量平方）
- `B`: Mul(`in²`,`in²`) → `{(in, Full)}`（两路输入污点相同，不互消）

**Phase 2**：单变量 4 次多项式。设 `x = in²`（Tonelli-Shanks 开方），则 `in = ±sqrt(x)`，Full Leak 成立。  
**1 条 issue**。

---

### 3.2 `known_last_assignment_1_mixed`（L112，含 `var` 中间变量）

```circom
template A() {
    signal input in;
    signal output out;
    component a = B();     // B: out = in1 × in2[1]
    component a1 = C();
    var mivar = in;
    a1.in <== in;
    a.in1 <== a1.out;      // in²
    a.in2[1] <== mivar;    // var 传值 = in (直连!)
    a.in2[0] <== a1.out;
    out <== a.out;         // = in² × in = in³
}
```

**关键点**：`var mivar = in` 在 Circom 中将信号值拷贝到 var，后续 `<==` 时与直接写 `in` 等价，约束为 `a.in2[1] = in`（1 次多项式项）。  
**约束链**：`out = in³`（3 次多项式）  
**Phase 1**：Mul×2 → `{(in,Full)}`，**1 条 issue**。  
Cantor-Zassenhaus 算法可从 `out = in³` 高效求根，Full Leak 成立。

---

### 3.3 `if_known_last_assignment_1_signal_comp`（L111，加入编译期 `if`+`<--`）

```circom
template A(n) {
    ...
    if (n > 10) { a.in1 <-- a1.out; }   // n=2：恒假，死分支
    a.in2 <== a1.out;                    // = in²，<== 约束
    if (n <= 10) { a.in1 <-- a1.out; }  // n=2：恒真，执行
    out <== a.out;
}
component main = A(2);
```

**`<--` vs `<==` 的差异**：`a.in1 <-- a1.out` 仅在 witness 层赋值（无 R1CS 约束）。但 ZKLeak Phase 1 同样追踪 `<--` 赋值的污点传播：  
- `a.in1` 经 `<--` 获得污点 `{(in,Full)}`  
- `a.in2 <== in²` 获得污点 `{(in,Full)}`  
- `a.out = a.in1 × a.in2 = Mul({in,Full},{in,Full})` → `{(in,Full)}`  
- **Phase 1 透过 `<--` 正常传播**，检测结果：Full Leak。  

**附加缺陷**：`a.in1` 无 `===` 约束 → 证明者可将其设为任意值（**健全性漏洞**）。  
**3 条 issues**（2 条 `<--` 不必要警告 + 1 条 Full Leak）。

---

### 3.4 `if_known_last_assignment_1_mixed`（L110，含 `var` + `<--`）

```circom
template A(n) {
    var mivar = in;
    a1.in <== in + 2;                    // a1.out = (in+2)²
    if (n > 10) { a.in1 <-- a1.out; }
    a.in2[1] <== mivar;                  // = in，直连!
    if (n <= 10) { a.in1 <-- a1.out; }  // n=5：执行
    out <== a.out;                       // = (in+2)² × in = in³+4in²+4in
}
component main = A(5);
```

**约束链**：`out = (in+2)² × in = in³ + 4in² + 4in`（3 次多项式）  
`a.in2[1]` 直接约束到 `in`，`a.in1` 经 `<--` 获得 `(in+2)²` 的 witness，Phase 1 正常传播，Full Leak 成立。  
**3 条 issues**。

---

### 3.5 `unknown_last_assignment_1_signal_comp`（L109，数组 + for 循环版）

```circom
template B(n) {
    signal input in1[n];
    signal input in2[n];
    signal output out;
    out <== in1[0] * in2[n-1];           // 取首尾两元素
}

template A(n) {
    signal input in;
    signal output out;
    component a = B(n);
    component a1 = C();
    a1.in <== in;                         // a1.out = in²
    for (var i = 0; i < n; i++) {
        a.in1[i] <== a1.out;             // = in²
        a.in2[i] <== a1.out + 6;         // = in²+6
    }
    out <== a.out;                        // = in² × (in²+6) = in⁴+6in²
}
component main = A(3);
```

**"unknown last" 的含义**：在静态分析时，若不求值模板参数 `n`，for 循环的终止条件未知，引擎无法静态确定每个 `a.in1[i]` 的最后赋值时刻。ZKLeak 使用 **worklist 算法**（Phase 2 工作列表）处理此类情形，仍然正确识别了污点传播路径。

**约束链**（n=3）：
```
a1.out     = in²
a.in1[0]   = in²         a.in2[2]   = in²+6
a.out      = in² × (in²+6) = in⁴ + 6in²
out        = in⁴ + 6in²
```

**Phase 1 详解**（与日志对应）：
| sig_id | 操作类型 | 污点输出 | 对应节点 |
|--------|----------|----------|---------|
| 15 | Mul | `{(0,Full)}` | `a1.out = in*in` |
| 25 | Select | `{}` | 循环控制变量 `i` |
| 35 | AddSub | `{}` | 循环计数 `i+1` |
| 31 | AddSub | `{(0,Full)}` | `a.in2[i] = a1.out+6`（+6 为常量，不消除污点）|
| 9  | Mul | `{(0,Full)}` | `a.out = in1[0]*in2[2]` |

**Phase 2**：`K(out) = {(in, Full)}`，单变量。设 `x = in²`：
$$x^2 + 6x = out \Rightarrow x = \frac{-6 \pm \sqrt{36 + 4 \cdot out}}{2}$$
再由 $in = \pm\sqrt{x}$（Tonelli-Shanks），可在有限域内高效恢复 `in`。Full Leak 确认。  
**1 条 issue**（仅 Full Leak 警告，无 `<--` 类警告）。

---

## 4. 批量审计结论

| 文件 | 约束链 | 多项式次数 | 含 `<--` | Issues |
|------|--------|-----------|---------|--------|
| known_last_signal_comp | `in⁴` | 4 | 否 | 1 |
| known_last_mixed | `in³` | 3 | 否 | 1 |
| if_known_last_signal_comp | `in⁴`（部分`<--`）| 4 | 是 | 3 |
| if_known_last_mixed | `in³+4in²+4in`（部分`<--`）| 3 | 是 | 3 |
| unknown_last_signal_comp | `in⁴+6in²` | 4 | 否 | 1 |

**核心结论**：
1. **Phase 1 透过 `<--` 传播**：即使 `a.in1` 使用不约束的 `<--` 赋值，Phase 1 仍能正确追踪 witness 赋值的污点，实现 Full Leak 检测。
2. **多项式次数不影响检测**：无论是 3 次还是 4 次多项式，有限域上都存在高效算法（Cantor-Zassenhaus 求根 / Tonelli-Shanks 开方）可恢复私有输入。
3. **数组索引安全性**：`B(n)` 中的 `in1[0]*in2[n-1]` 数组索引不影响污点传播 —— 引擎正确处理了参数化数组下标的信息流分析。
4. **`var` 中间变量不是防护屏障**：`var mivar = in` 后用 `<==` 赋值等价于直接 `<== in`，Phase 1 正确识别。
