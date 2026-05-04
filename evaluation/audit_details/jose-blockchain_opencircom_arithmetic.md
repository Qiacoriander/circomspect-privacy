# 隐私泄露审计报告：jose-blockchain_opencircom (arithmetic_test - 多算子联合泄露)

## 1. 项目与漏洞概述
- **项目名**: `jose-blockchain_opencircom`
- **电路文件**: `test/circuits/arithmetic_test.circom`
- **泄露类型**: **1 Full Leak**
- **涉及信号**: `arr3[3]` (3元素私有数组)

---

## 2. 电路架构与泄露分析

```circom
template ArithmeticTest() {
    signal input arr3[3];        // Private
    signal input a2[2];          // Private
    signal input b2[2];          // Private
    signal output sum3;          // Public: Σarr3[i]
    signal output sum1;          // Public: arr3[0]  (Sum(1))
    signal output inner2;        // Public: a2·b2

    component s3 = Sum(3);       // sum3 = arr3[0]+arr3[1]+arr3[2]
    component s1 = Sum(1);       // sum1 = arr3[0]  ← 🔴 单元素求和等于直通！
    component ip2 = InnerProduct(2); // inner2 = a2[0]*b2[0]+a2[1]*b2[1]
    // ...
}
```

### 泄露链路
1. **`sum1 = Sum(1)(arr3[0])`**：对单元素执行"求和"操作实质等价于 `sum1 <== arr3[0]` 直通。引擎Phase 2立即推导 K(arr3[0]) = FK。
2. **`sum3 = arr3[0]+arr3[1]+arr3[2]`**：在 K(arr3[0])=FK 已知条件下，`sum3 - arr3[0] = arr3[1]+arr3[2]` 变成了一个只含两个未知数的线性方程。但由于 `arr3[1]` 和 `arr3[2]` 仅此一条约束关系，两者互为掩蔽。
3. **`inner2 = a2[0]*b2[0]+a2[1]*b2[1]`**：Phase 1 中 Mul 操作产生空污点 `{}`（因为两个私有变量互乘具有代数盲化效果），`a2`、`b2` 不被回溯为泄露。

### 引擎报告核心
引擎仅报 `arr3` 为 Full Leak，因为通过 `Sum(1)` 组件暴露了 `arr3[0]` 的真值。引擎对 `a2`/`b2` 的双变量内积操作正确地识别为互盲化安全。

## 3. 审计结论
确认为有效泄露 (True Positive)。`Sum(1)` 的退化求和等价于恒等映射。引擎在阵列级别对 `arr3` 进行了整体标记，尽管实际仅首元素被直通。此案例展示了**算子退化（Operator Degeneration）**导致隐私保护失效——单元素的聚合操作丧失了我们期望的信息压缩效果。
