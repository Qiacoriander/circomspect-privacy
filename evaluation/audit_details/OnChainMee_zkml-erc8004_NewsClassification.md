# 审计报告：OnChainMee_zkml-erc8004 NewsClassification

## 项目概述

| 字段 | 内容 |
|---|---|
| **项目名** | OnChainMee_zkml-erc8004 |
| **电路文件** | `news-service/circuits/NewsClassification.circom` |
| **泄露类型** | Partial Leak (引擎报告) → 实际危害达 Full Leak 级别 |
| **受影响信号** | `feature1` (情感特征分) |
| **论文价值** | ZK-ML 多通道联合泄露：三路公开输出协同还原私有输入；揭示"单通道 Partial 判定低估多输出电路实际风险"的系统性问题 |

---

## 电路功能描述

`NewsClassification` 声称可以在**不揭示原始新闻特征**的前提下，在链上证明新闻情感分类结果。

```circom
template NewsClassification() {
    // 私有输入（不应上链）
    signal input feature1;  // 情感分数 (-1 到 1)
    signal input feature2;  // 关键短语指示
    signal input feature3;  // 不确定性指示

    // 公开输出（上链可见）
    signal output sentiment;      // 0=正面, 1=负面, 2=中立
    signal output confidence;     // 置信度 0-100
    signal output featuresHash;   // 特征"哈希"（完整性）
}

component main = NewsClassification();
```

注意：`component main` 未声明任何 `{ public [...] }`，因此所有 `signal input` 均为**私有输入**，三路输出均为公开输出。

---

## 泄露机制分析

### 通道 1：sentiment 揭示 feature1 的符号

```circom
component isPositive = GreaterThan(32);
isPositive.in[0] <== feature1;
isPositive.in[1] <== 0;

component isNegative = LessThan(32);
isNegative.in[0] <== feature1;
isNegative.in[1] <== 0;

sentiment <== isNegative.out + (1 - isPositive.out - isNegative.out) * 2;
```

`sentiment` 的取值与 `feature1` 的对应关系：

| sentiment 值 | 含义 | 揭示的 feature1 范围 |
|---|---|---|
| `0` | 正面 | `feature1 > 0` |
| `1` | 负面 | `feature1 < 0` |
| `2` | 中立 | `feature1 == 0` |

**结论**：`sentiment = 2` → `feature1 = 0`（精确）；`sentiment ≠ 2` → 至少确定 feature1 的符号。

---

### 通道 2：confidence 揭示 |feature1| 的精确值

```circom
// abs(feature1) 计算
component abs = Abs();
abs.in <== feature1;
absFeature1 <== abs.out;

// 置信度计算（线性映射）
confidenceScore <== 60 + absFeature1 * 20;

// 上限截断
component confCheck = LessThan(8);
confCheck.in[0] <== confidenceScore;
confCheck.in[1] <== 100;

confidence <== confCheck.out * confidenceScore + (1 - confCheck.out) * 100;
```

当 `confidence < 100` 时，`confCheck.out = 1`，则：

```
confidence = 60 + |feature1| × 20
|feature1| = (confidence - 60) / 20
```

当 `confidence = 100` 时，仅知 `|feature1| ≥ 2`。

---

### 通道 1 + 2 联合攻击：近全量还原 feature1

| confidence 值 | sentiment 值 | 可恢复的 feature1 |
|---|---|---|
| 60 | 2 | `feature1 = 0` ✓ 完全精确 |
| 60 | 0 | `feature1 = 0`（矛盾，设计中sentiment=2对应0） |
| 80 | 0 | `feature1 = +1` ✓ 完全精确 |
| 80 | 1 | `feature1 = -1` ✓ 完全精确 |
| 100 | 0 | `feature1 ≥ +2`（范围已大幅压缩）|
| 100 | 1 | `feature1 ≤ -2`（范围已大幅压缩）|

对于离散整数型特征（`feature1 ∈ {-1, 0, 1}` 如情感打分），`confidence < 100` 时可**完全精确还原** `feature1`。

---

### 通道 3：featuresHash 形似哈希、实为线性函数

```circom
featuresHash <== (feature1 * 1000 + feature2 * 100 + feature3 * 10) % 999983;
```

**关键缺陷**：模数 `999983` 是一个极小的素数（约 10⁶ < 2²⁰），而真正的密码学哈希（如 Poseidon、MiMC）是非线性单向函数。

在已知 `feature2` 和 `feature3`（例如，如果这些是公共已知的分类标签）的条件下：

```
feature1 = (featuresHash - feature2×100 - feature3×10) × 1000⁻¹ mod 999983
```

其中 `1000⁻¹ mod 999983` 存在且可高效计算（`999983` 为素数，`gcd(1000, 999983) = 1`）。

此外，`999983` 的模空间仅有约 100 万个值，而 BN254 域元素有约 2²⁵⁴ 种可能，这使得即使不知道 `feature2`、`feature3`，也可以枚举所有满足条件的 `feature1` 值。

---

## 引擎检测行为分析

### 污点传播路径（Phase 1 输出节选）

```
DEBUG: Phase 1 output for sig_id 10 from op_id 9 (type: AddSub): {(0, Full), (1, Full)}
DEBUG: Phase 1 output for sig_id 16 from op_id 15 (type: Mul): {(0, Full)}
DEBUG: Phase 1 output for sig_id 47 from op_id 32 (type: Compare): {(0, Partial)}
DEBUG: Phase 1 output for sig_id 73 from op_id 72 (type: Mul): {(0, Full), (0, Partial)}
```

- `sig_id 10`（featureSum）：被 `feature1`(id=0) 和 `feature2`(id=1) 的 Full 污染
- `sig_id 47`（GreaterThan/LessThan 比较结果）：被 `feature1`(id=0) 的 Partial 污染
- `sig_id 73`（confidence 相关乘法）：同时存在 Full 和 Partial 污染

**引擎最终报告：**
```
warning: Private Input `feature1` has a PARTIAL LEAK risk mapped to public outputs.
```

引擎在单信号维度上判定为 Partial Leak，但**未考虑多输出信号的联合语义**。

---

## 漏洞严重性量化

| 泄露维度 | 引擎判定 | 实际严重性 |
|---|---|---|
| `sentiment` 单独 | Partial | 揭示 feature1 符号（1 bit 信息） |
| `confidence` 单独 | 未报告（featureSum 相关） | 揭示 \|feature1\|（连续值） |
| `sentiment + confidence` 联合 | 未考虑联合 | **近全量恢复 feature1**（Full Leak） |
| `featuresHash` 独立 | 未报告 | 线性可逆（小模数，非哈希） |

**根本原因**：CCIG-Leak 引擎以**单信号**为粒度报告泄露，而未对同一私有输入被多路输出分别泄露的情形进行**联合语义推理**。

---

## 密码学设计缺陷总结

| 缺陷类型 | 代码位置 | 说明 |
|---|---|---|
| 分类输出直接揭示输入符号 | `sentiment <== isNegative.out + ...` | 不应直接将 feature1 的符号暴露为公开分类结果 |
| 置信度为线性函数 | `confidenceScore <== 60 + absFeature1 * 20` | 对 feature1 的幅度信息进行线性编码，可逆 |
| 伪哈希：小模数线性表达式 | `(f1×1000 + f2×100 + f3×10) % 999983` | 模数过小（2²⁰），且是线性函数，非密码哈希 |
| 未使用的中间信号 | `signal sentimentScore` | 未约束，circomspect under-constrained 警告 |

---

## 修复建议

### 1. 将特征哈希替换为真正的密码哈希

```circom
// 错误：线性小模数函数
// featuresHash <== (f1*1000 + f2*100 + f3*10) % 999983;

// 修正：使用 Poseidon 哈希
component h = Poseidon(3);
h.inputs[0] <== feature1;
h.inputs[1] <== feature2;
h.inputs[2] <== feature3;
featuresHash <== h.out;
```

### 2. 公开输出设计：仅输出最终分类，移除置信度

分类结果 `sentiment` 仅揭示 feature1 的符号（1 bit），是最低限度的必要泄露。置信度输出大幅增加了额外信息泄露，应移除或用范围证明替代：

```circom
// 移除 confidence 输出，改为范围证明
// 证明置信度在 [60,100] 范围内而不揭示精确值
component confRange = GreaterEqThan(8);
confRange.in[0] <== confidenceScore;
confRange.in[1] <== 60;
// 仅公开 confInRange（boolean），而非精确值
```

### 3. 声明公开输入约束

```circom
component main { public [] } = NewsClassification();
// 所有特征均不应出现在 public input 中
```

---

## 引擎检测能力评估

| 评估维度 | 结论 |
|---|---|
| 是否发现泄露 | ✅ 是（检测到 feature1 的 Partial Leak） |
| 泄露严重性评估 | ⚠️ 低估（实际为 Full Leak 级别，引擎仅报 Partial） |
| 多通道联合泄露识别 | ❌ 未检测（引擎以单信号为粒度，未进行多输出联合分析） |
| 伪哈希识别 | ❌ 未报告（线性小模数函数被当作普通算术表达式，未标记为弱哈希） |

**论文意义**：本案例表明，对于具有**多路输出**的 ZK-ML 电路，单路 Partial Leak 判定可能严重低估实际风险。未来的分析引擎应支持对同一私有输入的**多输出联合熵分析**（Joint Entropy Reduction Analysis）。
