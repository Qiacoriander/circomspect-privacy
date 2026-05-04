# 多变体检测结果对比报告

- 生成时间: 2026-03-24 12:50:29
- full 输入: `D:\dev\circomspect\evaluation\evaluation_results\full.csv`
- no-unroll-conservative 输入: `D:\dev\circomspect\evaluation\evaluation_results\no_unroll_conservative.csv`
- no-unroll-aggressive 输入: `D:\dev\circomspect\evaluation\evaluation_results\no_unroll_aggressive.csv`
- single-pass 输入: `D:\dev\circomspect\evaluation\evaluation_results\single_pass.csv`
- vanguard-lite 输入: `D:\dev\circomspect\evaluation\evaluation_results\vanguard_lite.csv`

## 每个变体检测结果汇总

| 变体 | 总条目 | 成功 | 失败 | 泄露条目 | 泄露信号总数 | FULL | PARTIAL | CASCADE | 分析总耗时(秒) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| full | 2373 | 2344 | 29 | 173 | 225 | 197 | 28 | 7 | 1445.5849 |
| no-unroll-conservative | 2373 | 2365 | 8 | 147 | 195 | 173 | 22 | 4 | 895.2624 |
| no-unroll-aggressive | 2373 | 2365 | 8 | 248 | 306 | 281 | 25 | 6 | 892.0434 |
| single-pass | 2373 | 2344 | 29 | 171 | 219 | 192 | 27 | 0 | 1508.0729 |
| vanguard-lite | 2373 | 2365 | 8 | 583 | 1295 | 118 | 1295 | 0 | 868.8874 |

## 逐项差异概览

- 变体键集合总条目: 2373
- 存在差异条目: 586
- 差异类型统计:
  - leak_count_mismatch: 565
  - success_mismatch: 21
- 差异 CSV: `D:\dev\circomspect\evaluation\evaluation_results\compare_all_differences.csv`

## Task4 差异分类说明

- 工具失败：至少一个变体执行失败，导致无法直接比较泄露统计。
- 保守误报：conservative 泄露数高于 full 且高于 aggressive。
- 激进召回：aggressive 泄露数高于 conservative，且不低于 full。
- 其他差异：其余无法归入上述三类的数值差异。

- 工具失败: 21
- 保守误报: 0
- 激进召回: 99
- 其他差异: 466

## 仅某变体发现项

- 仅单一变体发现的泄露条目总数: 328
- 仅 full 发现: 0
- 仅 no-unroll-conservative 发现: 0
- 仅 no-unroll-aggressive 发现: 0
- 仅 single-pass 发现: 0
- 仅 vanguard-lite 发现: 328
- 仅单变体发现项 CSV: `D:\dev\circomspect\evaluation\evaluation_results\compare_all_exclusive_findings.csv`

## 差异样例（最多前20条）

| 项目 | 文件 | 模式 | full | no-unroll-conservative | no-unroll-aggressive | single-pass | vanguard-lite | 差异类型 |
|---|---|---|---:|---:|---:|---:|---:|---|
| 0xShiiro_ZK-learnings | `0xShiiro_ZK-learnings\array.circom` | main | 1 | 1 | 1 | 1 | 1 | leak_count_mismatch |
| 0xShiiro_ZK-learnings | `0xShiiro_ZK-learnings\multiply.circom` | main | 0 | 0 | 0 | 0 | 3 | leak_count_mismatch |
| 0xc0de42_zk-sandbox | `0xc0de42_zk-sandbox\public\circuits\square_root\square_root.circom` | main | 1 | 0 | 1 | 1 | 1 | leak_count_mismatch |
| 0xgeorgemathew_rip-contracts | `0xgeorgemathew_rip-contracts\circuits\priceProtection.circom` | main | 0 | 0 | 0 | 0 | 6 | leak_count_mismatch |
| 2281469043_zkKYC_and_zkCBPR | `2281469043_zkKYC_and_zkCBPR\Circuits\zkMerkleTree\Verifier.circom` | main | 0 | 0 | 0 | 0 | 2 | leak_count_mismatch |
| 2dvorak_zk-jwt-poc | `2dvorak_zk-jwt-poc\circuits\jwt.circom` | main | 0 | 0 | 5 | 0 | 5 | leak_count_mismatch |
| ABaaaC_zkKaggle | `ABaaaC_zkKaggle\test\circuits\MaxPool2D_ks3_test.circom` | main | 1 | 0 | 1 | 1 | 1 | leak_count_mismatch |
| ABaaaC_zkKaggle | `ABaaaC_zkKaggle\test\circuits\MaxPool2D_test.circom` | main | 1 | 0 | 1 | 1 | 1 | leak_count_mismatch |
| AkshatGada_circom-lib | `AkshatGada_circom-lib\circuits\Multiplier.circom` | main | 0 | 0 | 0 | 0 | 2 | leak_count_mismatch |
| AkshatGada_circom-lib | `AkshatGada_circom-lib\circuits\Pubkey.circom` | main | 0 | 0 | 1 | 0 | 1 | leak_count_mismatch |
| Alchemist21_pecunia | `Alchemist21_pecunia\zk\circuit3\circuits\sha256\main.circom` | main | 0 | 0 | 0 | 0 | 1 | leak_count_mismatch |
| Alchemist21_pecunia | `Alchemist21_pecunia\zk\circuit3\main3.circom` | main | 1 | 1 | 1 | 1 | 1 | leak_count_mismatch |
| Alchemist21_pecunia | `Alchemist21_pecunia\zk\new_circuit\circuit.circom` | main | 1 | 1 | 1 | 1 | 1 | leak_count_mismatch |
| AliIbrahimMohammed_ZKP_solidity | `AliIbrahimMohammed_ZKP_solidity\circuits\VaultProof.circom` | main | 0 | 0 | 0 | 0 | 1 | leak_count_mismatch |
| AmbitionCX_circomViz | `AmbitionCX_circomViz\Backend\src\examples\XOR.circom` | main | 0 | 0 | 0 | 0 | 2 | leak_count_mismatch |
| AmbitionCX_circomViz | `AmbitionCX_circomViz\Backend\src\examples\twobitsmultiplier.circom` | main | 0 | 0 | 0 | 0 | 4 | leak_count_mismatch |
| Ayalyt_blockchain-Verification-Integration | `Ayalyt_blockchain-Verification-Integration\Compiler-Verification\benchmarks\case.circom` | main | 1 | 0 | 1 | 1 | 1 | leak_count_mismatch |
| Ayalyt_blockchain-Verification-Integration | `Ayalyt_blockchain-Verification-Integration\Compiler-Verification\benchmarks\tests\Array.circom` | main | 0 | 0 | 0 | 0 | 1 | leak_count_mismatch |
| Ayalyt_blockchain-Verification-Integration | `Ayalyt_blockchain-Verification-Integration\Compiler-Verification\benchmarks\tests\Array_Func.circom` | main | 2 | 0 | 2 | 2 | 2 | leak_count_mismatch |
| Ayalyt_blockchain-Verification-Integration | `Ayalyt_blockchain-Verification-Integration\Compiler-Verification\benchmarks\tests\Com.circom` | main | 1 | 0 | 1 | 1 | 1 | leak_count_mismatch |
