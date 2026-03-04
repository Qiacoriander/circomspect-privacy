# Audit Report: `stellar_soroban` / `multiplier2.circom` & `busyapedao` / `sha256`

## 1. 概览
* **项目**: `stellar_soroban-examples` & `busyapedao_zksafebox-contract`
* **漏洞文件**: 
  - `groth16_verifier/data/auxiliary/multiplier2.circom`
  - `zk/circuits/sha256/main.circom`
* **原始评价结果 (`evaluation_results.csv`)**:
  - `multiplier2.circom`: 2 个 **FULL LEAK**
  - `sha256/main.circom`: 1 个 **FULL LEAK**
* **最新检测结果 (应用 Masking-Aware Phase II 与 OneWay Hash 白名单后)**: **0 个泄露！**

## 2. 深入审查与分析

### 案例 A: `multiplier2.circom`

#### 原本的误报机理
这是一个最纯粹的二元乘法器：
```circom
template Multiplier2 () {  
   signal input a;  
   signal input b;  
   signal output c;  
   c <== a * b;  
}
```
原本的 CCIG Phase II 推导引擎，会因为观测到公开输出 $c$，并且从 Phase I 传来的信息集包含 $I(c) \leftarrow \{(a, \mathsf{Full}), (b, \mathsf{Full})\}$，就极其霸道地进行无差别解盲，直接给 $a$ 和 $b$ 定性为 **FULL LEAK**。但这在代数上由于缺乏进一步约束，实际上是一个完美掩蔽。

#### 修订后的表现
随着我们在本轮中为引擎装载了 **Masking-Aware** (防遮蔽解盲) 逻辑，该引擎现在会先统计信息集中独立私有前驱的数量：
`let full_privs_count = info_set.iter().filter(|(_, tau)| matches!(tau, Intensity::Full)).count();`
本例中 `a` 和 `b` 占据了 2 个源头，因此进入 `is_blinded = true` 状态，强行阻止了虚假的危险升级。目前对于类似 $c = a * b$、$y = \sum x_i$ 的多变量代数混合保护，工具都能给出正确的 $0$ 泄露通行证。

---

### 案例 B: `sha256/main.circom`

#### 原本的误报机理
它内部执行的是完整的 SHA-256 操作：
```circom
    component sha256 = Sha256(256);
    for (i=0; i<256; i++) {
        sha256.in[i] <== in[i];
    }
    for (i=0; i<256; i++) {
        out[i] <== sha256.out[i];
    }
```
早先版本中，工具由于没能严格阻断数组级变量深入哈希组件内层的回溯，因此通过暴力正向传递引发了泄露误报。

#### 修订后的表现
在我们针对内部安全加密组件设定了全局 `is_oneway` 的拦截器后（如 Poseidon, Sha256），隐私变量穿过它的过程将仅得到 `OneWay` 的不可逆污染。反向推导即使碰到暴露的哈希输出边界，也无法借此穿透该组件去点亮 `in[256]` 的 FULL LEAK。这同样是一个教科书般的**假阳性修复成功案例**。

## 3. 结论
**Status: False Positive, FIXED by Engine Refinements!**

随着我们的分析工具愈发符合严格的密码学界限控制与代数盲化定义，这些由于简单堆积而在早期版本中产生误判的情况，现已全部扫除。

同时经过对比，另一典型单量暴露如 `isZero` ($out \leftarrow -in \times inv + 1$) 则因为源头数量唯一 ($inv$ 原本就来自 $in$)，依然被严格标记为 FULL LEAK，可见目前过滤系统的颗粒度非常精准，在排除了假阳性的同时，并未牺牲底线的保守侦测刚度。
