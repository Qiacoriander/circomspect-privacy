# 审计报告：ZKLeak 泄露程度精确区分能力 —— Full Leak vs Partial Leak 最小差异对比

**项目**：`Ayalyt_blockchain-Verification-Integration`  
**电路1 (L71)**：`compiler-testing/workspace/temp/2/temp1.circom` → Full Leak  
**电路2 (L185)**：`compiler-testing/workspace/temp/2/temp2.circom` → Partial Leak  
**泄露信号**：`NreLtQRSdp6v[1][1]`（两文件相同）  
**检测结论**：`1(1/0)` vs `1(0/1)`，issues 数相同（均 16 条）

---

## 一、背景与研究价值

这两个文件来自同一 Ayalyt 编译器测试套件，使用完全相同的混淆模板骨架 `JPqsdBb7F6FN`，声明相同的私有输入 `NreLtQRSdp6v[1][1]`，但对该输入的**具体使用方式**存在关键差异。ZKLeak 引擎对两者给出了不同的检测结论——Full Leak 与 Partial Leak——精确反映了实际信息泄露程度的差异。这是展示 ZKLeak **量化信息泄露（而非仅二元判定）**能力的最优案例之一。

---

## 二、共同结构（混淆骨架）

两个文件共享以下模板特征：

```circom
template JPqsdBb7F6FN(XihmtdRlNw6Y, nnvCibgpjUEw, MFIlehw5Jb35) {
    // XihmtdRlNw6Y: 参数声明但完全未使用（never read）
    // nnvCibgpjUEw: 参数声明但不影响约束（side-effect-free）

    signal input NreLtQRSdp6v[1][1];   // 私有输入（目标）
    signal input opUwiNT3UHOk[1][1];   // 私有输入
    signal input m3O9LlqOfPBo[1];      // 私有输入
    signal input blZiy4Sg700g[1];      // 私有输入

    // 4 个 unused 中间信号（噪声）：
    signal YminHZTvfo2q;
    signal xFxmnHexM0uu[1];
    signal kxDc5REDgNh4[1];
    signal QjU6CeqZkP6h[1][1];

    var XAwGR4tUEkhJ = 7;              // dead var（从不影响约束）
    // ... 大量复杂的 dead code 表达式（含函数调用、条件表达式）...
    
    // obsON55n1vsG <-- NreLtQRSdp6v[0][0];  // <-- 赋值，never read
}
```

**噪声特征（Phase 1 中全部产生 `{}` 空污点）**：
- 大量 `Other` 型操作（函数调用、位运算、比较）→ `{}`
- `BitExtract` 操作（针对不相关信号）→ `{}`
- `Select` 条件选择 → `{}`

---

## 三、关键差异：私有输入的使用路径

### temp1.circom（L71）—— AddSub 路径 → Full Leak

在 temp1.circom 中，`NreLtQRSdp6v` 通过**算术加减法链**连接到公开输出：

```
Phase 1 关键节点：
sig_id 195 (Other):   {(193, Full)}    ← NreLtQRSdp6v 的直接算术导出
sig_id 196 (Other):   {(1, Full)}      ← 另一路私有输入
sig_id 206 (AddSub):  {(193, Full), (204, Full)}  ← 线性组合
sig_id 208 (AddSub):  {(204, Full), (193, Full), (20, Full)}  ← 多源
sig_id 212 (AddSub):  {(204, Full), (210, Full)}  ← 最终传播至输出
```

**解释**：`NreLtQRSdp6v` 经过一系列 AddSub（加减法）操作到达公开输出信号。由于线性运算不改变 Full 污点级别，引擎判定公开输出与 `NreLtQRSdp6v` 存在**确定性线性关系**——知道输出即可唯一反解私有输入，构成 **Full Leak**。

**攻击可行性**：若输出约束为 `out <== a + NreLtQRSdp6v` 或 `out <== c * NreLtQRSdp6v + d`（`a`/`c`/`d` 为已知量），则：

$$\text{NreLtQRSdp6v} = \frac{\text{out} - a}{c} \mod p$$

可在 $O(1)$ 内精确还原私有输入。

---

### temp2.circom（L185）—— BitExtract 路径 → Partial Leak

在 temp2.circom 中，`NreLtQRSdp6v` 通过**位提取操作**连接到公开输出：

```
Phase 1 关键节点（第一条即已出现 Partial）：
sig_id 23 (BitExtract):  {(20, Partial)}  ← NreLtQRSdp6v 的位分解
... （后续均传播 Partial 污点）
```

**解释**：`NreLtQRSdp6v` 被分解为若干位（`bits[i] <-- (value >> i) & 1`），这些位单独流向公开输出。BitExtract 操作将完整的域元素**压缩**为 1 位二元信号，每位只揭示原值的一个比特——这是 **Partial Leak** 的典型场景。

**攻击可行性**：若仅有 $k$ 个位被泄露（$k < 254$，BN128 域宽），攻击者只能将 `NreLtQRSdp6v` 的可能值域从 $2^{254}$ 缩窄到 $2^{254-k}$，信息量损失受限。相比 Full Leak，无法唯一还原原值。

---

## 四、ZKLeak 检测结果对比

| 属性 | temp1.circom (L71) | temp2.circom (L185) |
|---|---|---|
| 模板名 | `JPqsdBb7F6FN` | `JPqsdBb7F6FN`（相同） |
| 私有输入 | `NreLtQRSdp6v[1][1]` | `NreLtQRSdp6v[1][1]`（相同） |
| 混淆噪声 | 2 unused 参数 + 4 unused 信号 + dead var | 2 unused 参数 + 4 unused 信号 + dead var（相同） |
| **关键操作** | **AddSub**（线性加减法） | **BitExtract**（位分解） |
| Phase 1 首条有效输出 | `AddSub → {(193, Full), (204, Full)}` | `BitExtract → {(20, Partial)}` |
| **检测结论** | **Full Leak** | **Partial Leak** |
| issues 数 | 16 | 16 |
| 信息论分析 | 公开输出 ↔ 私有输入 存在单射线性映射 | 公开位 ↔ 私有输入 的部分比特，压缩映射 |

---

## 五、Phase 1 算法的操作类型语义

| 操作类型 | 语义 | 污点传播规则 |
|---|---|---|
| `AddSub` | 加法/减法（线性） | 保持 Full：`Full + Full → Full`（单变量时）|
| `Mul` | 乘法（可能非线性） | 双私有变量→`{}`（代数盲化）；常数×私有→`Full` |
| `BitExtract` | 位提取 `(x >> k) & 1` | `Full → Partial`（信息压缩） |
| `Select` | 条件选择 `c?a:b` | 保守传播：任一分支为 Full/Partial 则传播 |
| `Other` | 函数调用/复杂表达式 | 保守：`{}` 或继承源污点 |

**关键观察**：`BitExtract` 是 Phase 1 中唯一能将 `Full` 降级为 `Partial` 的操作，因为位提取在信息论意义上是一种**有损压缩**——单个位仅携带 1 比特而非完整值的 $\log_2 p \approx 254$ 比特信息。

---

## 六、结论与论文价值

**结论**：ZKLeak 的两阶段算法能够**精确区分**信息泄露的程度：

- **Full Leak**：线性算术路径（AddSub/常数乘法）将私有输入以确定性单射方式传到公开输出，攻击者可在多项式时间内精确还原私有输入
- **Partial Leak**：位操作路径（BitExtract）仅泄露私有输入的部分信息，攻击者只能将可能值域缩窄一定范围

这对安全评估具有重要意义：Full Leak 意味着零知识性质完全失效；Partial Leak 则视泄露比特数可能从轻微（1 位）到接近完全（253 位）不等。ZKLeak 通过 Phase 1 的精细操作类型分类，自动给出这种量化区分。

两个文件作为**最小差异（Minimal Difference）**实验对，能够以最小的变量扰动验证检测系统的行为，具有较高的论文案例价值。
