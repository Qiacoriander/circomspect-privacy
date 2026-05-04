# 隐私泄露审计报告：CGuthmann_Infrachain_ZeroKnowledge

## 1. 项目与漏洞概述
- **项目名**: `CGuthmann_Infrachain_ZeroKnowledge`
- **泄露类型**: **2 Full Leaks (完全侧漏)**
- **涉及信号**: `e` (RSA指数), `N` (RSA模数)
- **安全幸存信号**: `m` (RSA明文乘数) 未被判定泄露，体现了引擎的高精确度。

---

## 2. 漏洞发生链路分析

### 审计目标电路：`CGuthmann_Infrachain_ZeroKnowledge\circuits\circuit_rsa_encrypt.circom`

这个电路在 Circom 层面纯手工搓了一个极其复杂的 RSA 幂模运算：计算 $c = m^e \pmod N$。
这是一个极其有趣的审计案例，它不光体现了漏洞发现能力，更体现了检测引擎**没有误报**的高超能力。

#### 2.1 忘了加公共白名单所导致的公钥泄露 (Full Leak)
在 RSA 算法中，`e` 和 `N` 往往作为公钥（Public Keys）本身就应当是所有人可见的。但代码开头由于缺失了白名单设定：
```circom
component main = rsa_encrypt(250); // 没有写 {public [e, N]}
```
引擎按照严格标准把 `e` 和 `N` 判定成了要保护的私密数据。然而，作者紧接着：
```circom
    //publishing public key
    signal output e_out <== e;
    signal output N_out <== N;
```
直接大喇叭把它们当做 Output 送出了电路域！系统毫不客气地对这两个变量亮起了最高警戒的 **FULL LEAK** 红灯。这是极其正确而且精准的，因为它确实把引擎眼中的隐私给暴露了。

#### 2.2 大数幂模运算抗住了引擎逆推 (No Leak)
更为巧妙的是，电路的终点是将加密后的密文 `c` 输出：
```circom
    signal output c <-- trace[n-1] % N;
```
这个时候 `c` 是全网公开的（FK），`e` 和 `N` 也是公开的（FK）。引擎在此时会不会以为 $m$（最初级、最核心的隐私聊天明文）也泄露了呢？
答案是**没有**！
`Circomspect` 的代数求解器非常聪明。它在遇到多达 250 轮的大数连续乘模迭代、带条件的比特截断（`Num2Bits`）、以及商模分离式（`c <-- trace % N; factor <-- trace \ N; trace === factor*N + c`）时，其内在的代数关系极度非线性。引擎无法将多项式的根空间压扁收缩到确定域。
因此，对于 `m` 参数，引擎**安静地保持了沉默，并没有抛出任何 Leak 警告**！

## 3. 审计结论：确认为有效泄露 + 优秀的“防误杀”实证 (True Positive)
1. 对 `e` 和 `N` 的 Full Leak 警告属于正确的底层代码书写不规范与变量乱抛漏引发的告警，确认为 **True Positive**。
2. 对 `m` 没有扔出假阳性（False Positive）警报，证明了 `Circomspect` 工具在面对极其复杂的密码学原语级联模运算约束时，表现出了老练的代数容忍度，并不像传统的正则追踪器那样“一看到连线就报泄露”。这份测试用例太精彩了！
