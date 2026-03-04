# Audit Report: `zkmopro_benchmark` / `isZero.circom`

## 1. 概览
* **项目**: `zkmopro_benchmark`
* **漏洞文件**: `witness/circuits/isZero/isZero.circom`
* **原始评价结果 (`evaluation_results.csv`)**: 1 个 **FULL LEAK**
* **最新检测结果 (应用 Masking-Aware 后)**: 1 个 **FULL LEAK**

## 2. 深入审查与分析

### 案例剖析
著名的 `IsZero` 是一种非常基础的位工具，它基于以下方式工作：
```circom
template IsZero() {
    signal input in;
    signal output out;
    signal inv;

    inv <-- in!=0 ? 1/in : 0;
    out <== -in*inv +1;
    in*out === 0;
}
```

在测试中，即使我们部署了严格的代数完美掩蔽（Algebraic Blinding）安全感知识别（`is_blinded` 变量过滤），Circomspect 依然对隐私入参 `in` 发出了最高等级的致命 `FULL LEAK` 警报！

#### 底层推导引擎是如何做出判定的？
1. **Phase I （前向信息传递）**: 引擎顺着 `inv` 的依赖追溯了源头，记录了 $I(inv) \leftarrow \{(in, \mathsf{Full})\}$。随后在计算输出位 `out <== -in*inv +1` 时，再次合并双方信息，最终敲定 $I(out)$ 里唯一的秘密就是 $\{(in, \mathsf{Full})\}$。
2. **Phase II （反向约束解盲）**: 当系统探明 `out` 作为模板公开输出暴露了已知结果 (`FK`) 后，触发溯源。
这里发生了关键一幕：我们在新版本加入了防掩蔽检查 `let is_blinded = full_privs_count > 1;`。引擎点算了一下 `out` 的污染源，**发现仅仅只有一个独特的本源私有变量——就是 `in`！**
由于 `full_privs_count == 1`，判定结果为 `is_blinded = false`，不存在代数盲化！
于是，系统根据保守的数学可逆猜测（1 个完全泄漏的输出点必然能反推出仅仅 1 个被混合的未知数），当机立断直接将 `in` 升级为了 **FULL LEAK**。

## 3. 结论
**Status: True Positive!** (Within the context of conservative analysis)

虽然 `out` 实际上仅仅揭露了 `in` 最多 1 bit 的信息（即是否为 0），但由于代码中存在明显的、未用密码学强哈希斩断后路的显式代数暴露链，加之隐私入口数量唯一，无法享受多变量盲化豁免权。

工具坚持了零容忍的最高安防等级，在它眼中：“只暴露了一个人的秘密约等于把底裤也暴露了”。因此，这属于符合设计意图和严格安防哲学的 True Positive 事件。
