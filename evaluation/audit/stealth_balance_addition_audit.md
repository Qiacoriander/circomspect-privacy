# 审计报告：nobitex_sigmab - stealth_balance_addition.circom

## 1. 泄露概况
* **项目**: `nobitex_sigmab`
* **电路**: `circuit/stealth_balance_addition.circom`
* **原始检测泄露**: 2 个泄露，均为 `FULL LEAK`。
* **涉及信号**: 数组 `balances` 的两个元素。

## 2. 初始审查与问题定位
该电路的作用是提供一种隐藏余额相加的零知识证明（Stealth Balance Addition）。其核心逻辑非常直接：
1. 接收一个包含隐私余额的数组 `balances`，以及一个统一的混淆随机数 `salt`。
2. 对数组中的每一个具体的余额 `balances[i]` 分别调用 `Hasher()` 与 `salt` 进行哈希，并输出公共承诺节点 `coins[i]`。
3. 对所有的 `balances[i]` 求代数和 `sum`。
4. 对 `sum` 再次调用 `Hasher()` 并附加 `salt` 进行哈希，输出公共承诺节点 `sumOfBalancesCoin`。

在早期的未修补版本的 `circomspect` 工具中，这个电路报出了针对 `balances` 数组的两个 `FULL LEAK` 警告。

产生这两个警告的原因是我们之前在分析 `mpt_path.circom` 与 `mpt_last.circom` 遇到的**两个 CCIG 引擎漏洞的叠加**：
1. **伪全知输出漏洞**：工具内部错误地将内置 `Hasher` 算子输出的各种中间结果和部件端口添加为了公共输出 (`public_outputs`)。
2. **缺乏单向约束屏障**：由于 `Hasher()` 组件实例化名称没有与白名单完全匹配，引擎没有在信息流路径上对其打上 `Intensity::OneWay` 的阻断标签，使得后向推导求解器将带有哈希运算的步骤硬性等价为可逆的线性方程。

上述原因叠加后，导致求解器直接沿路线 `coins[i] === Hasher(balances[i], salt)` 平滑反推提取了原始的隐私 `balances`。

## 3. 结论与复测
由于我们在前两轮审计交互中，不仅完善了**组件名称启发式 One-Way 防火墙（涵盖 hash, mimc, poseidon, commit 等）**，还修补了**真正子组件到公共输出端口的越权注册漏洞**。

我们在当前修复后的引擎基础之上，重新编译运行了针对 `stealth_balance_addition.circom` 的审计。

* **重新评测的审计结果**: False Positive (假阳性)。
* **测试输出**: `circomspect: No issues found.`
* **当前状态**: 本电路所有的 2 个泄露隐患已被之前的分析引擎补丁**完全消除**，验证了这些改进带来了非常清晰、完美的分析准确率提升，工具不再对被单向密码学正确保护的对象进行错误警告。
