# 测试指南

本文档说明如何编译、部署和测试 Circomspect 隐私泄露检测工具。


## 环境准备

### 系统要求

- Rust 工具链（1.70+）
- Python 3.7+（用于测试脚本）

### 安装 Rust

```bash
# Linux/macOS
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Windows
# 访问 https://rustup.rs/ 下载安装
```

### 验证环境

```bash
rustc --version
cargo --version
python --version
```

---

## 编译项目

### 方式 1：开发模式编译

```bash
cd d:\dev\circomspect
cargo build
```

生成文件：`target\debug\circomspect.exe`

### 方式 2：发布模式编译（推荐）

```bash
cd d:\dev\circomspect
cargo build --release
```

生成文件：`target\release\circomspect.exe`


### 方式 3：安装到系统

```bash
cd d:\dev\circomspect
cargo install --path cli
```

安装后可直接使用 `circomspect` 命令。

---

## 单文件测试

### 使用 cargo run（开发阶段）

```bash
# 基本用法
cargo run --release -- path/to/circuit.circom

# 指定分析模式
cargo run --release -- path/to/circuit.circom --mode all
cargo run --release -- path/to/circuit.circom --mode main

# 详细输出
cargo run --release -- path/to/circuit.circom --mode all -v
```

### 使用编译后的可执行文件

```bash
# Windows
.\target\release\circomspect.exe path/to/circuit.circom --mode all

# Linux/macOS
./target/release/circomspect path/to/circuit.circom --mode all
```

### 分析模式说明

#### 1. ALL 模式（默认）

```bash
cargo run --release -- examples/ar_test.circom --mode all
```

- 分析文件中的**所有 template 和 function**
- 所有 `signal input` 都视为 **private**

#### 2. MAIN 模式

```bash
cargo run --release -- examples/ar_test.circom --mode main
```

- 只分析 **main component** 及其引用的 template
- 根据 **public 列表**区分输入的公开/私有属性


**要求：**
- 文件必须包含 `component main = ...` 声明
- 否则会报错

### 测试示例

```bash
# 测试 internal 项目中的文件
cargo run --release -- benchmarks/projects/internal/ArrayXOR@telepathy@n=4.circom --mode all
```

---

## 批量基准测试

### 测试脚本位置

```
benchmarks/
├── tools/
│   ├── run_benchmark.py      # 主测试脚本
│   └── USAGE.txt            # 简要使用说明
└── projects/                # 待测试项目
    ├── aes-circom/
    ├── circom-ml/
    └── ...
```

### 基本用法

#### 1. 运行自动模式测试 (推荐)

```bash
cd path_to_project\circomspect\benchmarks\tools
python run_benchmark.py --mode auto --output ../results_auto.csv
```

- **auto 模式**：脚本会分析文件内容。如果包含 `component main`，则使用 `main` 模式；否则使用 `library` 模式（对应 Rust 的 `all`）。

#### 2. 运行 Library 模式测试

```bash
python run_benchmark.py --mode library --output ../results_lib.csv
```

- 强制分析每个文件中的所有 Template（适用于库代码）。

#### 3. 运行 Main 模式测试

```bash
python run_benchmark.py --mode main --output ../results_main.csv
```

- 仅分析包含 `component main` 的文件。

### 脚本参数说明

```bash
python run_benchmark.py [选项]

选项：
  --mode {auto,main,library}  分析模式（默认：auto）
  --output PATH               输出文件路径（默认：benchmark_results.csv）
  --circomspect PATH          circomspect 可执行文件路径（默认使用 cargo run）
  --leak-threshold BITS       量化泄露阈值（默认：8 bits）。低于此值的泄露将被标记为 Low 严重程度。
  --min-severity {Low,Medium,High,Critical} 
                              最小报告严重程度（默认：Low）。低于此级别的泄露将不会被报告为 Warning。
  -v, --verbose               显示详细输出
```

### 参数详解

#### `leak_threshold` (泄露阈值)
- **作用**: 定义“多少比特的泄露是严重的可关注问题”。
- **影响**: 超过此阈值的泄露通常会被评级为 `High` 或 `Critical`，低于此阈值为 `Low` 或 `Medium`。

#### `min_severity` (最小报告严重程度)
- **作用**: 过滤报告噪音。
- **影响**:
    - **Low (默认)**: 报告所有发现的泄露。
    - **High**: 仅报告严重泄露（High/Critical），忽略轻微泄露（Low/Medium）。

### 使用已编译的可执行文件（更快）

```bash
# 先编译 release 版本
cd path_to_project\circomspect
cargo build --release

# 使用编译后的可执行文件运行测试
cd path_to_project\circomspect\benchmarks\tools
python run_benchmark.py --mode both --circomspect ../../target/release/circomspect.exe --verbose
```


---

## 测试结果

### CSV 结果文件

**字段说明：**

| 字段名 | 类型 | 说明 |
|--------|------|------|
| `project_name` | 字符串 | 项目名称 |
| `file_path` | 字符串 | 文件相对路径 |
| `mode` | 字符串 | 分析模式（main/library） |
| `has_privacy_leak` | 布尔 | 是否存在隐私泄露（输出信号直接被污染） |
| `has_quantified_partial_leak` | 布尔 | 是否存在可量化的部分隐私泄露（CS0021） |
| `leak_count` | 整数 | 泄露发生的总次数（基于警告数量） |
| `severity_low` | 整数 | Low 级别的泄露数量 |
| `severity_medium` | 整数 | Medium 级别的泄露数量 |
| `severity_high` | 整数 | High 级别的泄露数量 |
| `severity_critical` | 整数 | Critical 级别的泄露数量 |
| `analysis_time` | 浮点 | 分析用时（秒） |
| `success` | 布尔 | 是否成功分析（包含发现泄露的情况） |
| `error_message` | 字符串 | 错误信息（如有失败） |
