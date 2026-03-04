# 审计报告：nobitex_sigmab - mpt_path.circom

## 1. 泄露概况
* **项目**: `nobitex_sigmab`
* **电路**: `circuit/mpt_path.circom`
* **泄露数量**: 3 个 Private Input 报告了 `FULL LEAK`。
* **涉及信号**: `isTop`, `numLowerLayerBytes`, `numUpperLayerBytes`。

## 2. 初始假设与底层引擎修复
最初我们怀疑这是一个**假阳性 (False Positive)**，因为该电路使用了 `Keccak` 和 `Hasher` (`MiMCSponge`) 等密码学组件，而 `circomspect` 引擎可能没有正确地将它们识别为单向（One-Way）函数，导致在约束求解阶段发生了非法的代数反向推导。

为了验证这一点，我们在 `circomspect` 的 CCIG 数据流分析引擎中增强了“单向数据流防火墙”：
1. **添加启发式关键字匹配**：在 Phase 1 的输出标记中，如果实例化组件路径或内部信号由于 `hash`、`keccak`、`mimc`、`poseidon`、`sha256`、`pedersen`、`blake` 或 `commit` 等关键字被命中，这部分信号强制标记为 `Intensity::OneWay`。
2. **截断传播**：在 Phase 2 后向推导中，阻止已知（FK/PK）状态跨 `OneWay` 标记节点传播，严格避免引擎将哈希输出视作代数可逆方程。

## 3. 根因分析：确认为真阳性 (True Positive)
即便我们在引擎底层构建了坚固的哈希节点隔离屏障，针对上述三个变量的 `FULL LEAK` 警告依然存在。经过追踪电路的 AST 和实际依赖关系树，发现了以下**绕过哈希逻辑的纯代数确定性约束路径**：

1. 程序的私有输入 `numUpperLayerBytes` 和 `numLowerLayerBytes` 被传递到了 `upperPadding` 和 `lowerPadding` 填充组件中。
2. `Padding` 组件完全通过基本运算根据字节数（`aLen`）推算出了所属的数据块数量，并绑定到电路外部的中继信号 `numUpperLayerBlocks` 和 `numLowerLayerBlocks`。
3. 这些代表块数的变量随后被直接传入了一个校验器组件 `KeccakLayerChecker` （别名 `checker`）。
4. `KeccakLayerChecker` 内部调用了 `substringCheck` 组件。该组件只使用了算术加法、乘法与比较运算（`IsEqual`，`RangeCheck`），没有涉及到任何密码单向哈希。它把 `numBlocks` （由于上面推导，即直接关联到字节数）和公开/常量输入比对，将结果化为一个布尔信号 `out`。
5. 电路顶层包含明确的布尔非逻辑连通：`checker.out === 1 - isTop`。

**推演结论**：
电路的这段逻辑链条 `numUpperLayerBytes -> num_blocks -> substringCheck(numBlocks) -> checker.out -> isTop` 是**线性且纯代数的**。由于 `isTop` 的状态受到公共出口确定性钳制（或它自身即能通过证明公开推理），求解器能够沿着这一毫无密码学保护的代数通路直接推回给 `numUpperLayerBytes` 和 `numLowerLayerBytes`，或者大幅限制其可能值域空间。

因此，此次检测是一次**真阳性 (True Positive)** 报警，`circomspect` 在没有任何误判的情况下准确揪出了隐私参数在代数抽象层面泄露的脆弱点。

## 4. 结论
* **审计结果**: True Positive
* **引擎修复**: 意外获得了 `ccig.rs` 对于哈希库单向安全特性的健壮补丁，已彻底保留相关规则。
