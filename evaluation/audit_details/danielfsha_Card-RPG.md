# 隐私泄露审计报告：danielfsha_Card-RPG (扑克发牌)

## 1. 项目与漏洞概述
- **项目名**: `danielfsha_Card-RPG`
- **泄露类型**: **1 Full Leak (完全侧漏)**
- **涉及信号**: `shuffled_deck[52]` (已洗好的完整牌堆)

---

## 2. 漏洞发生链路分析

### 审计目标电路：`danielfsha_Card-RPG\circuits\pocker\src\deal.circom`

这是一个**零知识扑克发牌**电路，德州扑克的 ZK 实现——试图证明牌是从洗好的牌堆顶部按序发出的，同时隐藏牌堆的完整排列。

设计上看起来有模有样：用 Poseidon 生成了玩家 1 的底牌承诺（`hole_commitment_p1`）、玩家 2 的底牌承诺和公共牌承诺。但看看发牌逻辑：

```circom
    signal input shuffled_deck[52]; // 52张牌的完整排列，本应绝密
    signal output dealt_cards[9];   // 发出的9张牌

    for (var i = 0; i < 9; i++) {
        dealt_cards[i] <== shuffled_deck[i]; // 直接赋值！
    }
```

**原本应该保密的、代表整副牌排列顺序的 `shuffled_deck` 的前 9 张牌被直接赋值给了公开的 `dealt_cards` 输出！** 包括：
- 玩家 1 的底牌（位置 0-1）
- 玩家 2 的底牌（位置 2-3）
- 公共牌（位置 4-8）

发牌后，虽然作者用 Poseidon 对底牌做了哈希承诺，但由于 `dealt_cards` 已经把牌面明文公之于众，这些承诺变得毫无意义——相当于"先告诉你答案，再给你一个信封说答案在里面"。

## 3. 审计结论：确认为有效泄露 (True Positive)
这是一个在游戏领域极其典型的 ZK 隐私事故：发牌时牌面应当只有持牌者可见，但此处所有 9 张牌（包括对手的底牌）被全桌公开。引擎正确标识了 `shuffled_deck` 的 Full Leak。攻击者可以直接读取对手的底牌，德扑变成了明牌！**True Positive**。
