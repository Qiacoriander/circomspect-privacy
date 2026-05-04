# 审计报告：Ty-HA_zkage-proof-mobile / simple_age_check.circom

| 字段 | 内容 |
|---|---|
| 项目 | Ty-HA_zkage-proof-mobile |
| 文件 | `circuits/simple_age_check.circom` |
| 引擎判定 | Full Leak（私有输入 `minAge`）+ Under-constrained `ageDiff` |
| 人工审计结论 | **确认为有效泄露（Full Leak）** + **约束逻辑失效** |
| 论文价值 | 展示"注释语义 vs 声明语义不符"与"有限域减法 ≠ 非负约束"两类经典初学者错误 |

---

## 原始电路

```circom
pragma circom 2.0.0;

template SimpleAgeCheck() {
    signal input userAge;    // Private input - the user's actual age
    signal input minAge;     // Public input - minimum required age  ← 注释说公开，但声明为私有!

    signal output result;    // Public output - minAge for verification

    signal ageDiff;
    ageDiff <== userAge - minAge;   // 意图：ageDiff >= 0，但有限域中无此保证

    result <== minAge;              // minAge 直通公开输出 → Full Leak
}
component main = SimpleAgeCheck();
```

---

## 缺陷分析

### 缺陷一：声明意图不符导致 Full Leak

开发者已在注释中写明 `minAge` 是"Public input"，但代码中却声明为 `signal input`（私有）。随后 `result <== minAge` 将其直通公开输出，Phase 2 推理：

$$\text{result} - \text{minAge} = 0 \implies K(\text{minAge}) = \text{FK}$$

**修复**：改为 `component main { public [minAge] } = SimpleAgeCheck();`

### 缺陷二：有限域减法不等同于非负约束

```
ageDiff <== userAge - minAge;
// 开发者注释："For the proof to be valid, ageDiff must be >= 0"
```

在素数域 $\mathbb{F}_p$（$p \approx 2^{254}$）中，`userAge - minAge` 可能回绕。例如：

| userAge | minAge | ageDiff（实际） | 通过验证？|
|---|---|---|---|
| 25 | 18 | 7 | ✓ 符合预期 |
| **10** | 18 | $p - 8 \approx 2^{254}$ | **✓ 意外通过**（未成年人绕过验证）|

即：任意 `userAge < minAge` 都能生成合法证明，约束形同虚设。

**修复**：使用 circomlib 的 `GreaterEqThan(n)` 位比较组件，并确保输入范围在 `n` 位以内：

```circom
component ageCheck = GreaterEqThan(8);   // 年龄 ≤ 255
ageCheck.in[0] <== userAge;
ageCheck.in[1] <== minAge;
result <== ageCheck.out;                 // 1 = 合法，0 = 不合法
```

---

## ZKLeak 引擎分析

Phase 1 仅记录 `ageDiff` 的 AddSub 操作（污点 `{(userAge, Full), (minAge, Full)}`），引擎随后报告 `minAge` Full Leak（来自 `result <== minAge` 的直接约束）及 `ageDiff` under-constrained 警告（仅出现在一个约束中，无实际限制效果）。

引擎未报告有限域回绕问题（超出 CCIG-Leak 检测范围，属于约束语义正确性分析领域）。
