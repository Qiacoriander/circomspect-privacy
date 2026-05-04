# 隐私泄露审计报告：Kartikvyas1604_TrustNet (企业区块链成员资格证明)

## 1. 项目与漏洞概述
- **项目名**: `Kartikvyas1604_TrustNet`（企业级可信网络区块链系统）
- **泄露类型**: **1 Full Leak (完全侧漏)**
- **涉及信号**: `employeeSecret`（员工私密凭证）
- **安全幸存信号**: `pathElements[20]`、`merkleRoot` 未直接泄露 ✅（但Merkle验证机制本身存在严重缺陷）

---

## 2. 漏洞发生链路分析

### 审计目标电路：`Kartikvyas1604_TrustNet\circuits\transaction_membership.circom`

```circom
template TransactionMembership() {
    // Private inputs
    signal input employeeSecret;       // 员工私密凭证
    signal input pathElements[20];
    signal input pathIndices[20];      // ← 警告：从未使用！

    // Public inputs
    signal input merkleRoot;
    signal output nullifier;           // ← 公开输出：可作废标识

    // Simplified leaf computation (replace with Poseidon in production)
    signal leaf;
    leaf <== employeeSecret * employeeSecret;     // 仅平方，可逆性差

    // Simplified merkle path verification（加法累加，无哈希）
    signal computedHash[21];
    computedHash[0] <== leaf;
    for (var i = 0; i < 20; i++) {
        computedHash[i+1] <== computedHash[i] + pathElements[i];
    }

    // Verify root matches
    rootCheck <== computedHash[20] - merkleRoot;
    rootCheck === 0;

    // Nullifier generation（致命漏洞在此）
    nullifier <== employeeSecret * 2;     // ← Full Leak 路径
}

component main = TransactionMembership();
```

### 泄露机制：trivial nullifier 线性泄露

**Full Leak 直接路径**：
```
nullifier = employeeSecret * 2
    ↓  (公开输出，任何人可见)
employeeSecret = nullifier / 2    // 在素数域中：nullifier * modular_inverse(2)
```

`nullifier` 是 `employeeSecret` 的简单 2 倍关系——在素数域 BN254 中，2 的乘法逆元存在且唯一，攻击者只需用公开的 `nullifier` 值乘以 `2⁻¹ mod p` 即可**直接还原** `employeeSecret`。

引擎调试输出印证了这一点：
```
Phase 1 output for sig_id 7  from op_id 6  (type: Mul): {(0, Full)}   ← leaf = secret²
Phase 1 output for sig_id 33 from op_id 32 (type: AddSub): {(3, Full)} ← computedHash[20]
Phase 1 output for sig_id 39 from op_id 38 (type: Mul): {(0, Full)}   ← nullifier = 2*secret
```

信号 `sig_id 39` 对应 `nullifier`，其污点标记 `{(0, Full)}` 中 `0` 即为 `employeeSecret` 的信号 ID，确认完全泄露。

### 双重密码学缺陷

本电路不仅存在隐私泄露，还有完整的**密码学设计失效**：

| 位置 | 设计意图 | 实际实现 | 安全性 |
|------|---------|---------|------|
| 叶子哈希 | Poseidon(employeeSecret) | `employeeSecret²` | ❌ 平方可被平方根攻击 |
| Merkle验证 | 哈希链递推 | 加法累加 `computedHash[i+1] = computedHash[i] + pathElements[i]` | ❌ 可通过调整pathElements伪造任意根 |
| Nullifier | Hash(secret, root) | `2 * employeeSecret` | ❌ 线性映射直接反解 |
| 路径方向 | pathIndices 控制左右 | pathIndices **从未使用** | ❌ 路径方向信息完全冗余 |

### 语义讽刺

TrustNet 是一个**企业可信网络**系统，其核心价值在于"可信地证明员工身份而不暴露凭证"。但：
- `employeeSecret` 通过 `nullifier = 2 * secret` **公开暴露了精确值**
- Merkle 树验证仅用加法，任何人都能伪造合法路径
- pathIndices 的存在但未使用表明这是一个**未完成的草稿实现**

注释中写道 "Simplified for Circom 0.5.46 compatibility / Upgrade to Circom 2.x for full Poseidon and MerkleProof support"，说明开发者**知晓这是临时简化实现**，但代码已经进入评估集，代表了真实项目中"TODO 安全缺陷"的典型模式。

---

## 3. 审计结论：确认为有效泄露 (True Positive)

这是一个**多层次密码学失效**的典型案例，最直接的 Full Leak 路径是：

> `nullifier = employeeSecret × 2` → 观察者直接反推 `employeeSecret = nullifier × 2⁻¹ mod p`

该案例对论文的核心价值：
1. **"临时简化实现"的安全危害**：开发者知道要用 Poseidon，但用线性乘法代替，导致 Full Leak
2. **nullifier 设计模式的安全要求**：nullifier 必须是私有值的单向哈希，线性变换不满足要求
3. **多缺陷叠加**：一个短小（36行）的电路同时触发了 Full Leak、under-constrained（pathIndices 未使用）等多类警告，体现了 circomspect 的综合检测能力

**True Positive**（有效泄露）。
