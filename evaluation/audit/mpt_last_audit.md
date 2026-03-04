# 审计报告：nobitex_sigmab - mpt_last.circom

## 1. 泄露概况
* **项目**: `nobitex_sigmab`
* **电路**: `circuit/mpt_last.circom`
* **原始检测泄露**: 11 个泄露，其中 9 个 `FULL LEAK`，2 个 `PARTIAL LEAK`。
* **涉及信号**: `lowerLayerPrefixLen`, `nonce`, `balance`, `hash_address`, `expected_prefix`, `upperLayerBytes`, `upperLayer` 等。

## 2. 初始审查与问题定位
`mpt_last.circom` 是一个极其复杂的 Merkle Patricia Tree 叶子节点校验电路。它大量调用了 `Keccak`、`HashBytes`、`Hasher` (基于 `MiMCSponge`)、`Rlp` 序列化等各类子组件。

我们在运行 `circomspect` 的深入评估时，发现像 `nonce` 和 `balance` 这种深埋在 `Rlp` 内部并通过不可逆哈希进行上层承诺的隐私输入，依然被标记为了 `FULL LEAK` 甚至是穿透式的跨组件泄露。这与先前修复的 `mpt_path.circom` 完全不同，那里是由于代码层面存在另一条绕过哈希校验的旁路代数路径。而在 `mpt_last` 中，唯一的公开输出是 5 个根节点的承诺哈希 (`commitUpper`, `commitLower`, `balanceCommitment`, `ECDSACommitmentHash`, `saltUiqenessCommitment`)。只要前端标记好了 `Hasher` 组件为单向（OneWay），反推就不应该跨越它们到达底部的明文输入。

为了彻底定位这些穿透性推导的原因，我们追踪了编译构建出的 CCIG 有向约束图的知识库队列演化情况 (`phase_2_backward_inference`)。

**惊人的发现**：
在工作队列弹出的首批 Public Outputs 节点信息中，我们观察到了**多达 126 个**源自公共输出 (`FK` - Fully Known) 的信号。而根据源码定义，顶层的公共输出本应该只有这**5 个**。
仔细比对后我们发现，多出来的这 121 个信号，全都是子组件（如 `Rlp`, `Concat`, `BitDecompose`, `RangeCheck`）的内部或自身输出口！例如：
* `account_rlp_calculator_nonceRlp_isSingleByte_n2b_bits`
* `concat_bShifter_out`
* `addr_hasher_hash_address`
* ...

### BUG 根因：伪造的全知视界 ("God Mode")
`circomspect` 代码构建 CCIG 阶段的问题在于：在底层依赖库解析 `cfg.output_signals()` 这个接口时，它返回了目标电路（包括其完全内联平铺的所有子电路组件）所有的具有 `SignalKind::Output` 属性的信号集合。

而在旧版本的 `ccig.rs` 构建逻辑中，节点注册函数 `add_node` 只要看到信号的类型是 `Output` 或 `Input` 并且属于公共可见度（`Pub`），就会粗暴无脑地把它塞入全局的 `public_outputs` 追踪列表中：
```rust
        if let NodeType::Signal { name, kind, vis, inst, .. } = &node_type {
            self.var_to_id.insert(name.clone(), id);
            // 【缺陷缺陷缺陷】这里没有区分它是电路的主公共入口，还是某子组件实例化产生的一个局域信号
            if vis == &SignalVis::Pub {
                if kind == &SignalKind::Input {
                    self.public_inputs.insert(id);
                } else if kind == &SignalKind::Output {
                    self.public_outputs.insert(id);
                }
            }
        }
```
**后果**：这个巨大的解析漏洞导致在 Phase 2 的知识回溯推理中，求解算法被凭空赋予了该电路多达一百多个深层“内部节点”的绝对掌控权。因为每一个子模块计算完抛出来的结果对于它自身而言都有一个 `output` 的标签，求解引擎一拿到这些结果是 `FK` 状态，就能轻而易举地沿约束公式向前直接倒推回隐私输入（例如通过 `account_rlp_calculator.rlp_encoded_len` 是 `Output` 获得 `FK` -> 逆推暴露 `nonce` 和 `balance`）。这就等于向检测算法开启了“上帝透视模式”，直接从程序内脏里抓取数据从而造成大范围的虚假泄漏！

## 3. 引擎修复方案
针对这种 CCIG 图生成污染，我们为 `add_node` 和 `get_or_create_var_node` 的自动属性捕获增加了实例化域 `inst` 是否为空的检测门禁：

```rust
        if let NodeType::Signal { name, kind, vis, inst, .. } = &node_type {
            self.var_to_id.insert(name.clone(), id);
            if inst.is_empty() { // 修复点：确保只有顶层无前缀实例名作用域的纯公共信号才被视为边界 I/O
                if vis == &SignalVis::Priv {
                    self.private_inputs.insert(id);
                } else if vis == &SignalVis::Pub {
                    if kind == &SignalKind::Input {
                        self.public_inputs.insert(id);
                    } else if kind == &SignalKind::Output {
                        self.public_outputs.insert(id);
                    }
                }
            }
        }
```

## 4. 结论与复测
重新编译修复后的 `circomspect` 工具并在 `mpt_last.circom` 测试回归：
* **公共输出的数量**：精确降维为顶层真正的 **5** 个。
* **重新评测的审计结果**: False Positive (假阳性)。所有 11 个泄露警告**全部消失**，该电路中所有隐私输入均被有效保护在各类承诺与哈希约束后面，且安全隔离通过了工具验证！
* 这一底层建图错误的大规模除虫将使得整个基于复杂实例嵌套的 Circom 方案生态系统在此隐私工具中的分析准确率得到跨越式的整洁提升。
