# Audit Report: `zkmopro_benchmark` / `complex-circuit-*-*.circom`

## 1. 概览
* **项目**: `zkmopro_benchmark`
* **漏洞文件**: `mopro-core/examples/circom/complex-circuit/complex-circuit-*-*.circom` (共 7 个变种文件，从 100k 到 3200k 规模不等)
* **原始评价结果 (`evaluation_results.csv`)**: 每个文件均报 1 个 **FULL LEAK**
* **最新检测结果**: 每个文件依然各报 1 个 **FULL LEAK**

## 2. 深入审查与分析

### 案例剖析
这 7 个文件全部复用了完全相同的模板架构 `ComplexCircuit`，唯一的区别只是实例化时传入了不同规模的循环常数参量（例如 `NUM_VARIABLES=100000` 到 `NUM_VARIABLES=3200000`）。核心加密与约束逻辑如下：

```circom
template ComplexCircuit(NUM_VARIABLES, NUM_CONSTRAINTS) {
    signal input a;
    signal output c;
    signal b[NUM_VARIABLES];

    b[0] <== a*a;
    var i;
    for (i = 1; i < NUM_VARIABLES; i++) {
        b[i] <== b[i-1]*b[i-1];
    }
    i = i-1;
    for (var j = NUM_VARIABLES; j < NUM_CONSTRAINTS; j++) {
        b[i] === b[i-1]*b[i-1];
    }
    c <== b[i];
}
```

在该电路中，私有输入 `a` 依次通过中间变量数组 `b` 进行级联平方，最后直通公共输出端 `c`暴露。

#### 推导引擎的判定与应对
1. **单一私有信息源头**：沿着数据流的向后推导（Backwards Inference），当分析到 `c` 的赋值时，引擎会追溯 `b[i]` 的信息源 `I(b[i])`。无论该循环迭代了十万次还是三百万次，最终上溯到源头的私密基因都只有仅仅一个：`a`。
2. **防盲化隔离盾（Masking-Aware）无法触发**：因为整条计算链全由单体秘密参量主导演化（`full_privs_count == 1`），哪怕经过多次平方（乘法关系映射），它都不具备多变量代数盲化的隐藏掩饰效果。在密码学与抽象代数体系下，单一未知数的有限次固定次方如果在域面上公开可见，是可以被求解或极大缩减猜测空间的。
3. **精准警告**：于是，当引擎探明公共输出点 `c` 时，单源回溯链立刻将其定责为暴露点，当场毫不手软地判处了 `FULL LEAK`！

## 3. 结论
**Status: True Positive!**

这是一个典型的“计算复杂度很高但逻辑极度裸奔”的测试用例。尽管在极大的有限域上高次开方可能是难题，但 Circomspect 作为静态形式化审计工具，不负责判断高次幂密码学难度的安全边际。只要它是单体未阻断暴露，就应该保守报警。

事实证明，哪怕在处理高达 320 万级甚至更多次幂超长递归节点图的情境下，Circomspect 的推演引擎不仅依然稳固，没有因为过载出偏，并且能够稳定遵循了我们的设计准则（即：对非混合盲化单源输入持续保守报险）。全系列 7 个大体积计算测试案全部真阳性通过审计。
