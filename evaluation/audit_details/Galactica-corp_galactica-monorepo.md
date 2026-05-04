# 隐私泄露审计报告：Galactica-corp_galactica-monorepo

## 1. 项目与漏洞概述
- **项目名**: `Galactica-corp_galactica-monorepo`
- **泄露类型**: **2 Full Leaks (完全侧漏)**
- **涉及信号**: `xL_in` (左侧明文输入), `xR_in` (右侧明文输入)

---

## 2. 漏洞发生链路分析

### 审计目标电路：`Galactica-corp_galactica-monorepo\packages\zk-certificates\circuits\mains\mimcEnDecrypt.main.circom`

这个电路在测试或者演示一个非常神奇的操作：**将明文进行 MiMC 对称加密，然后再进行 MiMC 对称解密，并将最后解密的结果 Output 到公有网络！**

我们来看看代码结构：
```circom
	component encrypt = MiMCFeistelEncrypt(220);
	component decrypt = MiMCFeistelDecrypt(220);

	encrypt.xL_in <== xL_in;
	encrypt.xR_in <== xR_in;
	encrypt.k <== k;

	decrypt.xL_in <== encrypt.xL_out;
	decrypt.xR_in <== encrypt.xR_out;
	decrypt.k <== k_two;

	decrypt.xL_out ==> xL_out;
	decrypt.xR_out ==> xR_out;
```

在这里，`xL_out` 和 `xR_out` 作为 Output 是直接在链上对任何人公开的。这意味着**解密结果是明文可见的**。
同时，由于采用了 Feistel 结构搭建对称加解密系统，其天然具备高度的代数可逆性（双射）。

当开发者把解密结果发布出去的时候，无论 `k` 与 `k_two` 到底是不是相等的，引擎都会基于这道 `明文 -> 加密 -> 解密 -> 假明文` 的数据流，察觉到初始输入 `xL_in` 和 `xR_in` 实际上已经被最终输出的一对公理给完全限定住了代数空间。如果在实际使用中 `k == k_two`，这便是一个彻头彻尾脱裤子放屁的明文发送器。

系统循着这一条完整的约束依赖链关系（包括 Feistel 翻转矩阵的等效约束），直接逆向坍塌到了 `xL_in` 和 `xR_in` 身上，从而判定这对本应保密的私有入参面临着 **FULL LEAK**（完全侧漏）风险。

## 3. 审计结论：确认为有效泄露 (True Positive)
在 Zk 架构中做加密又同时原位做解密并导出是极度危险的，这等于变相向合约证明了一个明文的所有知识。引擎表现完美，没有由于中间穿插了海量的 `MiMC 220轮` 复杂运算而丢失链路，证明大深度的抽象运算未能逃脱约束跟踪器的锐眼。**True Positive**。
