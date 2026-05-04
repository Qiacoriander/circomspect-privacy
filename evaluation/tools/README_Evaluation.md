## 使用

### 1. 尝试分析基础测试代码

可以使用 `circomspect` 命令行直接调用这些具有明确入参的电路文件：

```bash
# 在 circomspect 项目根目录下执行
cargo run --bin circomspect -- evaluation/evaluation_projects/tornado_withdraw_mock.circom
cargo run --bin circomspect -- evaluation/evaluation_projects/semaphore_vote_mock.circom
cargo run --bin circomspect -- evaluation/evaluation_projects/bit_leak_test.circom
```

如果您的主分析程序有类似 `--level` 或详细的 Taint / Privacy Leakage 输出标语，记得加上相关参数，例如（假设）：
```bash
cargo run --bin circomspect -- --verbose evaluation/evaluation_projects/bit_leak_test.circom
```

**期望的评估分析结果：**
- 报告应指出 `bit_leak_test.circom` 中的 `in` 发生了精确的位运算信息分布。
- 对模拟的大型项目，应识别出 `public` 与 `private` 变量经过 hash / 加法 等各种算子的最终组合状态是"安全"还是"存在泄漏"，以及最高危险级别的泄漏警报是否正常抛出，从而印证您之前的“选取最高威胁度告警”补丁的实际成效。

### 2. 利用脚本获取更多真实 GitHub Circom 项目

由于真实的 Circom 项目可能包含了更复杂的 include（例如 `circomlib` 的多层嵌套），利用自动化脚本抓取线上单文件能快速扩展您的基准测试（benchmarks）库。

**运行脚本的前置条件：**
建议准备一个 GitHub 的 [Personal Access Token (PAT)](https://github.com/settings/tokens)，仅勾选 public_repo 权限即可，以免被 GitHub API Rate Limit 阻挡。

**使用步骤：**
您可以直接通过执行 `fetch_github_circom.py` 来大规模拉取数据：
```powershell
cd evaluation/tools

# (可选) 设置 Github Token 环境变量
$env:GITHUB_TOKEN="your_github_pat_here"

# 运行爬取脚本
python fetch_github_circom.py
```
这会在 `evaluation/evaluation_projects` 根目录下生成各个项目的独立文件夹。

拉取完毕后，您可以利用 `run_evaluation.py` 批处理脚本对它们进行全面检验生成带动态时间戳的报表：
```powershell
# 在根目录或 tools 下运行均可
python evaluation/tools/run_evaluation.py --mode main-only
```
该命令会自动扫描 `evaluation_projects` 下所有的 circom 代码，把详细日志分类存入子目录 `evaluation_logs/evaluation_logs_<月日_时分>`，同时将汇总生成的 CSV 报表直接放置在 `evaluation_results/evaluation_results_<月日_时分>.csv`，为您保持项目文件的绝对整洁并方便对比溯源。

### 3. `run_evaluation.py` 详细使用说明

批量评估脚本 `run_evaluation.py` 提供了多种参数以适应不同的评估需求：

```bash
python evaluation/tools/run_evaluation.py [选项]
```

**核心参数说明：**

- `--mode {main-only,auto,library-all}` 
  指定隐私泄露的分析模式：
  - **`main-only` (默认)**：仅仅从包含 `component main` 的入口文件开始处理，没有 main 函数的依赖文件/组件不考虑也不单独检测。此模式效率最高，直击顶层电路漏洞。
  - **`auto`**：混合模式。有 main 函数的文件从 main 进入分析，没有 main 函数的文件其余视作 library 处理，独立输出分析结果。
  - **`library-all`**：不管有无 main 函数，强行将所有文件均视为 library（即检查其中的每个中间组件、模板），适用于极度严苛的全面组件排查。

- `--variant {full,no-unroll,no-unroll-conservative,no-unroll-aggressive,single-pass,vanguard-lite}`
  指定 CCIG 分析变体：
  - **`full` (默认)**：完整能力，包含子电路展开与阶段二不动点迭代推理。
  - **`no-unroll`**：兼容别名，等价于 `no-unroll-conservative`。
  - **`no-unroll-conservative`**：禁用未知子电路展开，黑盒仅保留来源痕迹并降级传播。
  - **`no-unroll-aggressive`**：禁用未知子电路展开，但黑盒保留来源传播强度（已知哈希/circomlib 降级规则仍生效）。
  - **`single-pass`**：阶段二仅执行单轮传播，不进行工作列表不动点迭代。
  - **`vanguard-lite`**：面向论文对比的轻量基线，仅做单电路边界内的泄露嫌疑判定，并对哈希类路径做 OneWay 降级/豁免。
  - **兼容性说明**：不传 `--variant` 时默认即 `full`，因此旧命令可直接复用。

- `--projects-dir PROJECTS_DIR`
  指定要评估的项目集所在路径。默认指向同级的 `evaluation/evaluation_projects` 目录。

- `--output OUTPUT`
  指定输出的汇总结果文件路径（CSV格式）。默认会自动生成带有时间戳的层级目录，例如 `evaluation/evaluation_results/evaluation_results_<月日_时分>.csv`。

- `--outputs-dir OUTPUTS_DIR`
  指定保存单个项目及文件详细分析日志的目录。默认分配在时间戳隔离目录下，例如 `evaluation/evaluation_logs/evaluation_logs_<月日_时分>`。此参数依赖 `--save-logs` 开启时才会有文件写入。

- `--save-logs`
  (可选) 是否将每个 circom 项目的底层完整执行报错及检测文本（`.log`）保存到磁盘。默认不开启以节省硬盘空间和提速。

- `--circomspect CIRCOMSPECT`
  指定自定义的 circomspect 核心可执行文件路径。如果不指定，脚本会自动退回到执行 `cargo run --bin circomspect`。

- `-v, --verbose`
  启用详细输出模式（将底层分析器的分析日志即时回显到控制台）。

### 4. 五变体评估与对比报告流程（含 no-unroll 双分支 + VanguardLite）

建议对同一批项目分别运行四次评估，再使用 `compare_variants.py` 统一生成差异报告。

#### 第一步：分别运行五种变体

```powershell
# full（可省略 --variant，默认就是 full）
python evaluation/tools/run_evaluation.py --mode main-only --variant full --output evaluation/evaluation_results/full.csv

# no-unroll-conservative（旧 no-unroll 别名默认映射到该分支）
python evaluation/tools/run_evaluation.py --mode main-only --variant no-unroll-conservative --output evaluation/evaluation_results/no_unroll_conservative.csv

# no-unroll-aggressive
python evaluation/tools/run_evaluation.py --mode main-only --variant no-unroll-aggressive --output evaluation/evaluation_results/no_unroll_aggressive.csv

# single-pass
python evaluation/tools/run_evaluation.py --mode main-only --variant single-pass --output evaluation/evaluation_results/single_pass.csv

# vanguard-lite
python evaluation/tools/run_evaluation.py --mode main-only --variant vanguard-lite --output evaluation/evaluation_results/vanguard_lite.csv
```

如果您需要验证旧命令兼容性，可以直接运行不带 `--variant` 的命令：

```powershell
python evaluation/tools/run_evaluation.py --mode main-only --output evaluation/evaluation_results/legacy_default.csv
```

该命令会在输出 CSV 的 `variant` 列写入 `full`，与显式 `--variant full` 行为一致。

#### 第二步：使用 compare_variants.py 生成对比报告

```powershell
python evaluation/tools/compare_variants.py `
  --full evaluation/evaluation_results/full.csv `
  --no-unroll-conservative evaluation/evaluation_results/no_unroll_conservative.csv `
  --no-unroll-aggressive evaluation/evaluation_results/no_unroll_aggressive.csv `
  --single-pass evaluation/evaluation_results/single_pass.csv `
  --vanguard-lite evaluation/evaluation_results/vanguard_lite.csv `
  --output-prefix task6_compare
```

脚本会在 `evaluation/evaluation_results` 下生成 4 份文件：
- `<前缀>_report.md`：可直接阅读的多变体对比报告（可含 VanguardLite）
- `<前缀>_summary.csv`：每个变体的汇总统计
- `<前缀>_differences.csv`：逐项差异明细
- `<前缀>_exclusive_findings.csv`：仅单变体发现项

### 5. 论文对比建议流程（full vs vanguard-lite）

若目标是论文中的基线对比，可最小化为二变体流程：

```powershell
python evaluation/tools/compare_variants.py `
  --full evaluation/evaluation_results/full.csv `
  --vanguard-lite evaluation/evaluation_results/vanguard_lite.csv `
  --output-prefix paper_full_vs_vanguard
```


### 6. VanguardLite 规则与限制说明

VanguardLite 的定位、规则、限制与完整命令集见：

- `evaluation/tools/VANGUARD_LITE_BASELINE.md`
