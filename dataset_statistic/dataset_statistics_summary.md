# 评测数据集统计汇总

- 生成时间: 2026-03-21 21:36:25
- 项目目录: `D:\dev\circomspect\evaluation\evaluation_projects`
- circomlib 目录: `D:\dev\circomspect\circomlib\circuits`
- 项目级明细 CSV: `D:\dev\circomspect\evaluation\evaluation_results\dataset_statistics_projects.csv`
- 失败样本 CSV: `D:\dev\circomspect\evaluation\evaluation_results\dataset_statistics_failures.csv`
- LOC 分桶边界: Small < 500, Medium [500, 5000], Large > 5000

## 论文表格字段汇总

| Scale (LOC) | Projects | Avg. Sub-circuits | Avg. R_known Hit Rate | Avg. Signals | Avg. Priv Signal Ratio |
|---|---:|---:|---:|---:|---:|
| Small (< 500) | 125 | 6.00 | 64.32% | 1982.30 | 89.07% |
| Medium (500 - 5000) | 96 | 24.70 | 74.24% | 7902.83 | 52.38% |
| Large (> 5000) | 350 | 35.03 | 70.94% | 12114.48 | 25.91% |
| **Total / Avg.** | **571** | **26.94** | **71.19%** | **9188.31** | **32.72%** |

## 信号口径对照（展开 vs 未展开）

| Scale (LOC) | Avg. Signals (Expanded) | Avg. Signals (Compact) | Avg. Priv Ratio (Expanded) | Avg. Priv Ratio (Compact) |
|---|---:|---:|---:|---:|
| Small (< 500) | 1982.30 | 26.75 | 89.07% | 35.44% |
| Medium (500 - 5000) | 7902.83 | 125.59 | 52.38% | 34.51% |
| Large (> 5000) | 12114.48 | 202.88 | 25.91% | 42.02% |
| **Total / Avg.** | **9188.31** | **151.33** | **32.72%** | **40.71%** |

## 运行质量

- 成功项目数: 571
- 失败项目数: 12
- 成功项目 unresolved include 总数: 1032

## 可复现实验命令

```bash
python evaluation/tools/build_dataset_statistics.py --projects-dir D:\dev\circomspect\evaluation\evaluation_projects --circomlib-dir D:\dev\circomspect\circomlib\circuits --output-csv D:\dev\circomspect\evaluation\evaluation_results\dataset_statistics_projects.csv --output-md D:\dev\circomspect\evaluation\evaluation_results\dataset_statistics_summary.md --output-failures-csv D:\dev\circomspect\evaluation\evaluation_results\dataset_statistics_failures.csv --small-upper 500 --medium-upper 5000
```
