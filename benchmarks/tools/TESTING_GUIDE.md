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
    ├── internal/
    └── ...
```

### 基本用法

#### 1. 运行 ALL 模式测试

```bash
cd path_to_project\circomspect\benchmarks\tools
python run_benchmark.py --mode all --output ../results_all.csv --verbose
```

#### 2. 运行 MAIN 模式测试

```bash
cd path_to_project\circomspect\benchmarks\tools
python run_benchmark.py --mode main --output ../results_main.csv --verbose
```

**注意：**
- 只会成功分析包含 `component main` 的文件
- 没有 main component 的文件会报错（正常现象）

#### 3. 运行双模式测试

```bash
cd path_to_project\circomspect\benchmarks\tools
python run_benchmark.py --mode both --output ../results.csv --verbose
```

对每个文件分别运行 ALL 和 MAIN 两种模式

### 脚本参数说明

```bash
python run_benchmark.py [选项]

选项：
  --mode {all,main,both}    分析模式（默认：both）
  --output PATH             输出文件路径（默认：benchmark_results.csv）
  --circomspect PATH        circomspect 可执行文件路径（默认使用 cargo run）
  -v, --verbose             显示详细输出
```

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
| `mode` | 字符串 | 分析模式（all/main） |
| `has_privacy_leak` | 布尔 | 是否存在隐私泄露 |
| `has_quantified_leak` | 布尔 | 是否存在可量化的部分泄露 |
| `analysis_time` | 浮点 | 分析用时（秒） |
| `success` | 布尔 | 是否成功分析 |
| `error_message` | 字符串 | 错误信息（如有） |
