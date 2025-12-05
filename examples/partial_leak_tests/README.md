# PartialLeak 量化评估测试示例

本目录包含用于演示和验证 PartialLeak 量化评估功能的测试电路。

## 测试文件列表

1. **01_basic_leak.circom** - 基础泄露（低于阈值）
2. **02_shift_leak.circom** - 位移操作泄露
3. **03_high_leakage.circom** - 多位提取测试（理论上应触发量化报告）
4. **04_deduplication.circom** - 去重机制验证

## 快速测试

```bash
# 测试基础泄露（不触发量化报告）
circomspect examples/partial_leak_tests/01_basic_leak.circom

# 测试位移泄露
circomspect examples/partial_leak_tests/02_shift_leak.circom

# 测试高泄露场景
circomspect examples/partial_leak_tests/03_high_leakage.circom

# 测试去重机制
circomspect examples/partial_leak_tests/04_deduplication.circom
```

## 重要说明

- 所有测试用例使用 Circom 的实际语法（位移 `>>`、位与 `&` 等）
- Circom 没有三元运算符 `? :`
- 量化报告的触发取决于实际记录的泄露量是否超过阈值 T(x)=8 bits

详细测试说明请参考 `temp_docs/partial_leak_implementation.md` 第十二章节。
