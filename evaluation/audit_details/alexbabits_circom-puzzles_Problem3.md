# 隐私泄露审计报告：alexbabits_circom-puzzles (数组排序)

## 1. 项目与漏洞概述
- **项目名**: `alexbabits_circom-puzzles`
- **泄露类型**: **1 Full Leak (完全侧漏)**
- **涉及信号**: `in[n]` (原始待排序数组)

---

## 2. 漏洞发生链路分析与复盘

### 审计目标电路：`alexbabits_circom-puzzles\BonusProblems\Problem3.circom`

这题是实现一个约束强制有序的数组排列器。

```circom
template Sort(n, bitSize) {
    signal input in[n];

    signal output advice[n];
    signal output out[n];               // <-- 输出管道

    var arr[n];
    // copy in to arr
    for (var i = 0; i < n; i++) {
        arr[i] = in[i];
    }
    // selection sort arr ...
    
    // copy sorted arr to out
    for (var i = 0; i < n; i++) {
        out[i] <-- arr[i];              // <-- 将排好序的内容强行送出
        advice[i] <-- advice_[i];
    }
    ForceIsPermutation(n)(in, out, advice);  // 内部有 in[advice[i]] === out[i] 的等价约束判定
}
```

### 电路反解流向
即使抛开 `ForceIsPermutation` 中的比较约束，单看顶层的赋值操作：
1. `in` 被拷贝成 `arr` 的形式存储；
2. 随后代码使用了命令式的冒泡/选择排序互换了 `arr` 中的位置；
3. **最关键的是，排他它把已经排序好的 `arr` 原封不动的塞入公共天线 `out[n]`**！

在零知识密码学世界对隐藏的定义里，对数组元素的**乱序互换操作（Permutation）本身是不等同于盲化（Blinding）的**！
因为排序仅仅代表改变了数据原本的映射指引，其每一个元素所在的明文标量真值，全都是完好无损地照搬输出。外部窥测者只要拿到 `out` 数组，就等于拿到了 `in` 的所有明文内容。更何况同时还通过 `advice` 高调公证了位置转换的索引偏序关系。

## 3. 审计结论：确认为有效泄露 (True Positive)
以 ZK 名义写排序而未能理解变量隐藏实质。排列组合不提供任何隐匿强度保护，输入集真值全部映射至出端。**True Positive**。 
