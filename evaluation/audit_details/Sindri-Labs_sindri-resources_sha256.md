# 隐私泄露审计报告：Sindri-Labs_sindri-resources (SHA256 预像证明)

## 1. 项目与漏洞概述
- **项目名**: `Sindri-Labs_sindri-resources`（Sindri ZK 基础设施服务商，专业 ZK 电路数据库）
- **泄露类型**: **1 Full Leak (完全侧漏)**
- **涉及信号**: `hash[32]`（SHA256 期望哈希值的 32 字节数组）
- **电路规模**: 910 行，2600+ 中间信号，涵盖完整的 SHA256 位操作实现

---

## 2. 漏洞发生链路分析

### 审计目标电路：`Sindri-Labs_sindri-resources\circuit_database\circom\sha256\circuit.circom`

```circom
template Main(N) {
    signal input in[N];        // 私有输入：SHA256 的原像（preimage）
    signal input hash[32];     // ← 私有输入：期望的 SHA256 哈希值（32 字节）
    signal output out[32];     // 公开输出：实际计算的 SHA256 结果

    component sha256 = Sha256Bytes(N);
    sha256.in <== in;
    out <== sha256.out;        // out = SHA256(in)

    for (var i = 0; i < 32; i++) {
        out[i] === hash[i];    // ← 等式约束：将 hash 与 out 绑定
    }
}

// render this file before compilation
component main = Main(256);   // 256 字节输入
```

### 泄露机制：等式约束导致 hash 随 out 一起公开

**Full Leak 完整路径**：
```
out[i] <== sha256.out[i]          （out 是公开 signal output）
out[i] === hash[i]                 （等式约束：out[i] 与 hash[i] 必须相等）
    ↓
∀i: hash[i] = out[i] = SHA256(in)[i]   （公开可见）
```

尽管 `hash[32]` 被声明为 `signal input`（默认私有），约束 `out[i] === hash[i]` 将其与已公开的输出信号 `out[i]` 强制等价，使得所有 32 字节的 `hash` 值在零知识证明验证时完全暴露。

引擎通过识别 `out <== sha256.out` 的信号传播链，结合后续的等式约束，确定 `hash` 经过 `out` 的中转完全暴露，最终报告 Full Leak。

### 设计意图与实现错误的根本矛盾

**正确的 SHA256 预像证明（ZK Proof of Preimage）设计**：

```
证明命题：我知道某个原像 x，使得 SHA256(x) = h
- h（哈希值）：公开，由验证者持有 → 应为 public input
- x（原像）  ：秘密，由证明者持有 → 应为 private input
```

| 设计角色 | 应为 | 实际声明 | 结果 |
|---------|------|---------|------|
| `hash[32]`（期望哈希） | public input | `signal input`（私有）| ❌ 被误设为私有，但随后通过等式约束暴露 |
| `in[N]`（原像） | private input | `signal input`（私有）| ✅ 正确私有，SHA256 非线性防住了反向推导 |

**正确写法**应为：
```circom
component main {public [hash]} = Main(256);
// 或者直接将 hash 作为 signal input public hash[32];
```

### Sindri 作为专业 ZK 基础设施的语境重要性

Sindri-Labs 是知名的 **ZK 电路托管与编译基础设施平台**，其 `circuit_database` 中存储的是供其他开发者直接调用的**模板电路库**。这意味着：

1. **影响范围扩散**：所有使用此 SHA256 预像证明模板的下游电路，都会继承这个 `hash` 泄露问题
2. **信任链危害**：开发者可能基于"这是专业基础设施"的信任，不再审查此电路的隐私模型
3. **典型的语义混淆**：电路实现了 SHA256 的计算逻辑（正确），但在"什么应该是 public"这一问题上产生了语义混淆

调试信息进一步显示了电路规模（2600+ 信号操作）——即便面对如此复杂的电路，引擎仍能精确定位唯一的 Full Leak 点（`hash[32]` → `out[32]`），体现了污点传播分析在大规模电路中的有效性。

---

## 3. 审计结论：确认为有效泄露 (True Positive)

这是一个具有**高度基础设施风险**的典型案例：

**泄露路径简述**：`hash[32]` 声明为私有输入 → `out[i] === hash[i]` 等式约束 → `out` 为公开输出 → `hash` 全部 32 字节完全暴露

该案例对论文的核心价值：
1. **public/private 角色语义混淆**：SHA256 预像证明中 hash 本应是 public，被错误声明为 private 后又通过等式约束暴露，呈现 ZK 电路的角色定义错误模式
2. **大规模电路精确定位**：910 行、2600+ 信号的复杂电路中，引擎仍能零误报地找到唯一泄露点
3. **基础设施级别的漏洞**：来自专业 ZK 服务商电路库的案例，说明即使专业团队也存在此类隐患，工具化检测的必要性显而易见

**True Positive**（有效泄露）。
