# Circomspect 隐私泄露审计记录

本项目用于系统性地跟踪和记录 `evaluation_results.csv` 中标记为存在泄露风险（leak_count > 0）的 Circom 电路审计结果。

## 审计目标

识别工具检测出的泄露是 **真阳性 (True Positive, TP)** 还是 **假阳性 (False Positive, FP)**，并探讨如果存在假阳性，是否可以通过优化 `circomspect` 的源码（如补充特殊组件的白名单、改进启发式规则等）来消除误报。

## 待审计清单与进度

| 项目 | 电路文件 | 泄露总数 (Full/Partial) | 审计状态 | 审计报告文件 |
| :--- | :--- | :--- | :--- | :--- |
| **nobitex_sigmab** | `circuit/mpt_path.circom` | 3 (3/0) | ✅ 已审计 (True Positive) | [mpt_path_audit.md](./mpt_path_audit.md) |
| **nobitex_sigmab** | `circuit/mpt_last.circom` | 11 (9/2) | ✅ 已审计 (False Positive - 图构建错误 - 已修复) | [mpt_last_audit.md](./mpt_last_audit.md) |
| **nobitex_sigmab** | `circuit/stealth_balance_addition.circom` | 2 (2/0) | ✅ 已审计 (False Positive - 已验证修复) | [stealth_balance_addition_audit.md](./stealth_balance_addition_audit.md) |
| **busyapedao_zksafebox** | `zk/main3.circom` | 1 (1/0) | ✅ 已审计 (True Positive - 源码直接泄露) | [busyapedao_main3_audit.md](./busyapedao_main3_audit.md) |
| **busyapedao_zksafebox** | `zk/circuits/sha256/main.circom` | 1 (1/0) | ✅ 已审计 (False Positive - 修复消除) | [zero_leak_fixed_audit.md](./zero_leak_fixed_audit.md) |
| **Poseidon-ZKP** | `hello_zkp/simple_polynomial.circom` | 4 (4/0) | ✅ 已审计 (False Positive - 掩蔽感知修复) | [poseidon_simple_polynomial_audit.md](./poseidon_simple_polynomial_audit.md) |
| **stellar_soroban** | `groth16_verifier/data/auxiliary/multiplier2.circom` | 2 (2/0) | ✅ 已审计 (False Positive - 掩蔽感知修复) | [zero_leak_fixed_audit.md](./zero_leak_fixed_audit.md) |
| **socathie_circomlib-ml**| `test/circuits/encryptDecrypt_test.circom` | 4 (3/1) | ✅ 已审计 (False Positive - 修复消除) | [socathie_circomlib_ml_audit.md](./socathie_circomlib_ml_audit.md) |
| **socathie_circomlib-ml**| `test/circuits/encrypted_mnist_latest_test.circom`| 2 (1/1) | ✅ 已审计 (False Positive - 修复消除) | [socathie_circomlib_ml_audit.md](./socathie_circomlib_ml_audit.md) |
| **socathie_circomlib-ml**| `test/circuits/LeakyReLU_test.circom` | 1 (0/1) | ✅ 已审计 (False Positive - 修复消除) | [socathie_circomlib_ml_audit.md](./socathie_circomlib_ml_audit.md) |
| **socathie_circomlib-ml**| `test/circuits/model1_test.circom` | 2 (1/1) | ✅ 已审计 (True Positive - 硬链接输出) | [socathie_circomlib_ml_audit.md](./socathie_circomlib_ml_audit.md) |
| **socathie_circomlib-ml**| `test/circuits/ReLU_test.circom` | 1 (0/1) | ✅ 已审计 (False Positive - 修复消除) | [socathie_circomlib_ml_audit.md](./socathie_circomlib_ml_audit.md) |
| **socathie_circomlib-ml**| `test/circuits/mnist_test.circom` | 3 (3/0) | ✅ 已审计 (True Positive - 硬链接输出) | [socathie_circomlib_ml_audit.md](./socathie_circomlib_ml_audit.md) |
| **zkmopro_benchmark** | `witness/circuits/isZero/isZero.circom` | 1 (1/0) | ✅ 已审计 (True Positive - 唯一隐蔽源) | [zkmopro_isZero_audit.md](./zkmopro_isZero_audit.md) |
| **zkmopro_benchmark** | `complex-circuit-*.circom` (共7个文件) | 各 1 (1/0) | ✅ 已审计 (True Positive - 唯一隐蔽源) | [zkmopro_complex_circuit_audit.md](./zkmopro_complex_circuit_audit.md) |
| **Zyra-V21_ZKUzumaki** | `circuits/example.circom` | 2 (2/0) | ✅ 已审计 (False Positive - 掩蔽感知修复) | [zyra_v21_audit.md](./zyra_v21_audit.md) |
| **Zyra-V21_ZKUzumaki** | `circuits/multiplier_fixed.circom` | 2 (2/0) | ✅ 已审计 (False Positive - 掩蔽感知修复) | [zyra_v21_audit.md](./zyra_v21_audit.md) |
| **Zyra-V21_ZKUzumaki** | `circuits/test_echo.circom` | 2 (2/0) | ✅ 已审计 (False Positive - 掩蔽感知修复) | [zyra_v21_audit.md](./zyra_v21_audit.md) |
| **Zyra-V21_ZKUzumaki** | `circuits/test_simple.circom` | 2 (2/0) | ✅ 已审计 (False Positive - 掩蔽感知修复) | [zyra_v21_audit.md](./zyra_v21_audit.md) |

---

> 注：我们会为您指定下一个审计项目。将具体的审计过程、原因分析以及解决方案（如果涉及引擎改良）单独存放在对应的 `.md` 报告中，并在此处更新链接。
