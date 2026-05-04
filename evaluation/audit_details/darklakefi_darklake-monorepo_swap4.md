# 隐私泄露审计报告：darklakefi_darklake-monorepo (ZK-AMM Swap)

## 1. 项目与漏洞概述
- **项目名**: `darklakefi_darklake-monorepo`
- **泄露类型**: **1 Full Leak (完全侧漏)**
- **涉及信号**: `privateAmount` (用户的隐私交易额度)
- **安全幸存信号**: `privateSlippage` (滑点容忍度) **未泄漏** ✅

---

## 2. 漏洞发生链路分析

### 审计目标电路：`darklakefi_darklake-monorepo\circuits\experiments\swap4.circom`

这是一个**零知识自动做市商（ZK-AMM）暗池交换**电路。DarkLake 项目的目标是让用户在 Uniswap 式 AMM 中执行 swap 时，**不向链上暴露交易数额**以防止 MEV 抢跑。

然而这个实验版本的隐私模型存在致命漏洞：

```circom
    signal input privateAmount;    // 用户的交易额度（Private）
    signal input liquidity_A;      // 池子A流动性（应为Public）
    signal input liquidity_B;      // 池子B流动性（应为Public）

    new_x <== x + privateAmount;   // 新的 x 储备 = 旧储备 + 交易量
    k <== x * y;                   // 恒积公式 k = x * y
    amount_y <== y - (k \ new_x);  // 计算接收的 y 数量
    amount_received <== amount_y;  // 公开输出
```

泄漏路径：`amount_received` 是公开输出。而 `amount_received = y - k/new_x = y - (x*y)/(x + privateAmount)`。由于 `liquidity_A`(x) 和 `liquidity_B`(y) 虽然也没有显式声明 public，但在链上 AMM 池子中它们是任何人都可以读取的已知量。因此攻击者只需代入公式即可反推出 `privateAmount`。

引擎通过对 `new_x <== x + privateAmount` 的加法约束和后续的 `k === new_x * (y - amount_y)` 乘法约束进行联立求解，判定 `privateAmount` 为 Full Leak。

## 3. 审计结论：确认为有效泄露 (True Positive)
这个案例极具讽刺意味：DarkLake 的核心产品定位就是"防止交易额度暴露以抵御 MEV"，但这个实验版本恰恰就把核心私有值 `privateAmount` 泄漏了。引擎的检测对 DeFi 暗池类协议的安全评估有着直接的实际价值。**True Positive**。
