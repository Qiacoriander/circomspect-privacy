# VanguardLite 基线说明与复现实验指南

## 1. 定位

`vanguard-lite` 是用于论文对比的简化 PIL（Private Input Leakage）基线变体，目标是复现“单电路、轻规则、泄露嫌疑判定”的检测思路，并与 `full` / `no-unroll` / `single-pass` 在统一输出格式下对比。

该变体的设计原则是：

- 保持与现有评估管线兼容（CSV 字段与 compare 脚本输入格式不变）
- 默认行为不变（不显式指定时仍是 `full`）
- 聚焦“是否存在泄露嫌疑”，不追求完整级联推理能力

## 2. 检测规则（VanguardLite）

VanguardLite 在 `program_analysis/src/ccig.rs` 中走独立分支，核心语义如下：

- 分析边界：仅在当前电路分析边界内进行传播判定
- 阶段策略：执行阶段一前向传播，不进入阶段二不动点后向推理
- 报告标签：输出两类嫌疑标签
  - `CONSTRAINT LEAK SUSPECT`：私有输入与公开信号存在约束耦合嫌疑
  - `DATAFLOW LEAK SUSPECT`：私有输入沿 witness/dataflow 到达公开输出嫌疑
- 强度处理：
  - `Full` 强度路径会被记录为“直接泄露嫌疑”
  - `Partial` 强度路径会被记录为“部分泄露嫌疑”
  - `OneWay` 强度路径不会触发嫌疑告警

## 3. 哈希类路径豁免规则

为避免将典型单向变换误报为“直接泄露”，VanguardLite 对哈希语义路径采用降级/豁免策略：

- 命中哈希算子名（例如 `poseidon` / `mimc` / `keccak` / `pedersen` / `hash` / `commit` 等）时，传播强度降级为 `OneWay`
- `OneWay` 路径在 VanguardLite 报告阶段被过滤，不生成上述两类 `LEAK SUSPECT`

## 3.1 统计口径（与 CSV 字段对齐）

`run_evaluation.py` 对 VanguardLite 的统计映射如下：

- `CONSTRAINT LEAK SUSPECT` 计入 `FULL LEAK` 列
- `DATAFLOW LEAK SUSPECT` 计入 `PARTIAL LEAK` 列
- `leak_count` 以“私有输入去重后”统计，不是两类标签的简单相加

这使得同一私有输入同时出现两类嫌疑时，最终总泄露数仍按 1 计数，符合 Vanguard 文档示例语义。

这保证了“私有输入经过已知单向哈希后再影响公开信号”不会被当成直接泄露。

## 4. 限制与边界

VanguardLite 是基线，不是完整替代版。请在论文中明确以下限制：

- 不执行阶段二工作列表不动点推理
- 不覆盖完整关系解盲（Relational De-blinding）能力
- 不覆盖完整级联泄露（Cascade）复访推理
- 对复杂跨模板/跨组件场景的精度低于 `full`
- 更适合用作“轻量基线”而非最终安全结论

## 5. 最小运行示例

在仓库根目录执行：

```powershell
# 直接指定 VanguardLite
python evaluation/tools/run_evaluation.py --mode main-only --variant vanguard-lite --output evaluation/evaluation_results/vanguard_lite.csv

# 旧命令兼容：不传 --variant 时默认 full
python evaluation/tools/run_evaluation.py --mode main-only --output evaluation/evaluation_results/full_default.csv
```

输出 CSV 中 `variant` 列将分别标记为 `vanguard-lite` 与 `full`，可直接进入对比流程。

## 6. 可直接复现的测试/评估命令集

### 6.1 五变体批量评估（推荐）

```powershell
python evaluation/tools/run_evaluation.py --mode main-only --variant full --output evaluation/evaluation_results/full.csv
python evaluation/tools/run_evaluation.py --mode main-only --variant no-unroll-conservative --output evaluation/evaluation_results/no_unroll_conservative.csv
python evaluation/tools/run_evaluation.py --mode main-only --variant no-unroll-aggressive --output evaluation/evaluation_results/no_unroll_aggressive.csv
python evaluation/tools/run_evaluation.py --mode main-only --variant single-pass --output evaluation/evaluation_results/single_pass.csv
python evaluation/tools/run_evaluation.py --mode main-only --variant vanguard-lite --output evaluation/evaluation_results/vanguard_lite.csv
```

### 6.2 对比报告生成（含 VanguardLite）

```powershell
python evaluation/tools/compare_variants.py `
  --full evaluation/evaluation_results/full.csv `
  --no-unroll-conservative evaluation/evaluation_results/no_unroll_conservative.csv `
  --no-unroll-aggressive evaluation/evaluation_results/no_unroll_aggressive.csv `
  --single-pass evaluation/evaluation_results/single_pass.csv `
  --vanguard-lite evaluation/evaluation_results/vanguard_lite.csv `
  --output-prefix paper_compare_with_vanguard
```

### 6.3 最小二变体对比（论文消融常用）

```powershell
python evaluation/tools/compare_variants.py `
  --full evaluation/evaluation_results/full.csv `
  --vanguard-lite evaluation/evaluation_results/vanguard_lite.csv `
  --output-prefix paper_compare_full_vs_vanguard
```

## 7. 论文可引用结果产出流程

建议按以下顺序固化可复现结果：

1. 使用固定 `projects-dir` 和固定命令分别生成各变体 CSV
2. 保留命令行与输出文件路径，确保可追溯
3. 用 `compare_variants.py` 统一生成四类产物：
   - `<prefix>_report.md`
   - `<prefix>_summary.csv`
   - `<prefix>_differences.csv`
   - `<prefix>_exclusive_findings.csv`
4. 论文正文建议引用 `summary.csv` 聚合指标，附录引用 `differences.csv` 与 `exclusive_findings.csv`

## 8. 结果解读建议

- 若 `summary.csv` 中 `leak_items` 和 `total_leak_signals` 接近 `full`，说明 VanguardLite 在该数据集上的召回接近完整版
- 若 `differences.csv` 增多，优先检查 `difference_reason`，区分是缺项、成功状态差异，还是泄露计数差异
- 若 `exclusive_findings.csv` 非空，说明存在“仅某变体发现”的检测行为，可作为论文中的差异案例分析
