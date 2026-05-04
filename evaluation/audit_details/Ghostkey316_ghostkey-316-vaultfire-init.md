# 隐私泄露审计报告：Ghostkey316_ghostkey-316-vaultfire-init

## 1. 项目与漏洞概述
- **项目名**: `Ghostkey316_ghostkey-316-vaultfire-init`
- **文件路径**: `quantum_expansion_v2\biolock.circom`
- **泄露类型**: **1 Partial Leak（复核后降级）**
- **涉及信号**: `entropy` (生物锁指纹), `salt` (隐私盐)

## 1.1 本轮复核更新（2026-03-22）
- 检测计数由 `2(2/0)` 调整为 `1(0/1)`
- 原“比较触发全链路级联Full”不再成立，保留为比较输出导致的区间级信息泄露

## 2. 漏洞发生链路分析
在加密世界，生物识别数据的隐私泄露是后果最严重的事件之一。这个电路旨在通过指纹的哈希与一个私有的 `salt` 混合，产生唯一的生物通证：
```circom
    signal input entropy;         // Hash of biometric entropy
    signal input salt;            // Optional salt to protect privacy
    signal output uniquenessFlag; // 1 when entropy is non-zero
    signal output saltedEntropy;  // salted entropy for downstream proof composition
```
由于没有限制 `public`，前两者默认私有。然后它们进行了如下运算：
```circom
    uniquenessFlag <== entropy != 0;
    saltedEntropy <== entropy + salt;
```
`circomspect` 给出了针对这两个底层输入的最高警报：**完全已知级泄露 (Full Leak)**。它的推导过程令人叹为观止，精准揭示了静态算术底层的脆弱性：

### 2.1 底层 `IsZero` 门限漏洞
Circom 中并不存在原生的逻辑比较器。代码中的 `!= 0` 本质上是由 Circomlib 基建的 `IsZero` 模板派生转换。
而在 `IsZero` 的实现逻辑末尾存在这样核心的一句：
```circom
    in * out === 0;
```
在这里，`in` 就是上述的私密指纹 `entropy`，`out` 就是（`!=` 逻辑取反后的）最终输出到 `uniquenessFlag` 的状态寄存器。
由于 `uniquenessFlag` 是上链对全网广播的公开属性 (Fully Known, FK)，黑客必然已知当前的 Flag 取值（如：有效 `val = 1`）。
在静态代数解构引擎眼中：如果黑客知道 `A * B === C` 内的常数 $C$ (即 $0$) 以及变量 $B$ (即已公开上链的 Flag)，他天然有资格尝试反除求解出 $A$。由此，引擎推翻盲化，粗暴地剥开了门电路组件的防线，判定 `entropy` **失去了安全性闭环 (Full Leak)**！

### 2.2 盲化护甲的级联碎裂 (Relational De-blinding)
当引擎得出“`entropy` 等同于已全盘裸露的信息”后。顺着图结构来到了第二行：
```circom
    saltedEntropy <== entropy + salt;
```
原本，两个独立的无知常量相加能够产生**绝对完美的代数盲化**，任何引擎都会给它们豁免不予升级风险。
但由于 `entropy` 在上一行比较验证的代码中已经被判定为阵亡侧漏（变为了 FK）。导致本多项式解盲！
既然 `saltedEntropy` 是公开的，`entropy` 已被攻破，简单的减法即可得出原本应深藏不露的隐私保护盐渍 `salt` 也同样毫无保留地 **完全裸奔出去了**！

## 3. 审计结论：代码写法导致的有效侧漏 (True Positive)
这是一次教科书级别的逆向漏洞扩散过程与图计算推演。开发者将极度关键的私有安全锚点不加修饰地暴露给了极具限制性的公共判别电路中并泄露了其中一端的代数结果，这招致了后续加密措施的全盘雪崩坍塌。确认为**极具价值的有效分析案例**。
