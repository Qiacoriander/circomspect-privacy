use log::{debug, trace};
use std::collections::{HashMap, HashSet};
use std::cell::RefCell;
use std::rc::Rc;
use std::str::FromStr;

use program_structure::cfg::Cfg;
use program_structure::file_definition::{FileID, FileLocation};
use program_structure::intermediate_representation::variable_meta::VariableMeta;
use crate::analysis_context::AnalysisContext;
use program_structure::ir::{
    Expression, Statement, VariableName, ExpressionInfixOpcode, ExpressionPrefixOpcode, AccessType,
    WeakCfgRef,
};
use program_structure::report::{Report, ReportCollection};
use program_structure::report_code::ReportCode;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum TaintLevel {
    Clean,
    Downgraded,
    PartialLeak,
    Tainted,
}

/// 泄露严重程度分类
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LeakSeverity {
    Low,      // 低：1 <= L(x) < 2
    Medium,   // 中：2 <= L(x) < 8
    High,     // 高：8 <= L(x) < H(x)
    Critical, // 严重：L(x) >= H(x) 或 Tainted 信号直接暴露
}

impl FromStr for LeakSeverity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" => Ok(LeakSeverity::Low),
            "medium" => Ok(LeakSeverity::Medium),
            "high" => Ok(LeakSeverity::High),
            "critical" => Ok(LeakSeverity::Critical),
            _ => Err(format!(
                "Invalid leak severity: '{}'. Valid values are: low, medium, high, critical",
                s
            )),
        }
    }
}

impl Default for LeakSeverity {
    fn default() -> Self {
        LeakSeverity::High
    }
}

/// 表示一个泄露操作，用于去重
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum LeakageOp {
    Comparison {
        secret: String,
        op: String,
        constant: Option<String>,
    },
    BitExtract {
        secret: String,
        bit_index: usize,
    },
    VariableBitExtract {
        secret: String,
    },
    // 新增：通过子组件间接泄露
    ComponentIndirect {
        component_type: String,
        component_var: String,
        port: String,
    },
    /// 泄露来自函数调用内部
    FunctionCall {
        function_name: String,
    },
}

/// 跟踪私有变量的部分泄露信息
#[derive(Clone, Debug)]
struct LeakageTracker {
    entropy_bits: usize,             // H(x)：信息熵
    leaked_bits: usize,              // L(x)：累积泄露量
    leakage_ops: HashSet<LeakageOp>, // 用于去重
    threshold: usize,                // T(x)：报警阈值
}

impl LeakageTracker {
    fn new(entropy_bits: usize, threshold: usize) -> Self {
        LeakageTracker { entropy_bits, leaked_bits: 0, leakage_ops: HashSet::new(), threshold }
    }

    /// 如果尚未计数，则添加泄露（去重）
    fn add_leakage(&mut self, op: LeakageOp, bits: usize) {
        if self.leakage_ops.insert(op) {
            self.leaked_bits = self.leaked_bits.saturating_add(bits).min(self.entropy_bits);
        }
    }

    // TODO
    /// T(x) = min(8, max(1, 0.125 * H(x)))
    fn threshold(&self) -> usize {
        self.threshold
    }

    /// 根据 L(x) 和 T(x) 分类泄露严重程度
    fn severity(&self) -> Option<LeakSeverity> {
        if self.leaked_bits == 0 {
            return None;
        }

        if self.leaked_bits >= self.entropy_bits {
            return Some(LeakSeverity::Critical);
        }

        if self.leaked_bits < 2 {
            Some(LeakSeverity::Low)
        } else if self.leaked_bits < 8 {
            Some(LeakSeverity::Medium)
        } else {
            Some(LeakSeverity::High)
        }
    }
}

impl TaintLevel {
    /// 计算两个污点等级的“并”
    /// 设计原则： Tainted > PartialLeak > Downgraded > Clean。
    /// - 任一为 `Tainted` → 结果 `Tainted`
    /// - `PartialLeak` 与 `Clean/Downgraded/PartialLeak` → 结果 `PartialLeak`
    /// - `Downgraded` 与 `Clean/Downgraded` → 结果 `Downgraded`
    /// - 两者均 `Clean` → 结果 `Clean`
    fn join(self, other: TaintLevel) -> TaintLevel {
        use TaintLevel::*;
        match (self, other) {
            (Tainted, _) | (_, Tainted) => Tainted,
            (PartialLeak, PartialLeak) => PartialLeak, // TODO：PartialLeak 的累积
            (PartialLeak, Clean) | (Clean, PartialLeak) => PartialLeak,
            (PartialLeak, Downgraded) | (Downgraded, PartialLeak) => PartialLeak,
            (Downgraded, Downgraded) => Downgraded,
            (Downgraded, Clean) | (Clean, Downgraded) => Downgraded,
            (Clean, Clean) => Clean,
        }
    }
}

#[derive(Clone, Default)]
pub struct PrivacyTaint {
    levels: HashMap<VariableName, TaintLevel>,
    component_types: HashMap<VariableName, String>,
    component_cfgs: HashMap<VariableName, WeakCfgRef>,
    component_inputs: HashMap<VariableName, TaintLevel>,
    component_port_levels: HashMap<VariableName, HashMap<String, TaintLevel>>, // 每个端口的等级（例如："in"）
    child_cache: RefCell<HashMap<(String, TaintLevel), TaintLevel>>, // 根据 (cfg_name, seed_level) 缓存子cfg输出的隐私泄露等级
    leakage_trackers: HashMap<VariableName, LeakageTracker>,         // 跟踪部分泄露量化
    leakage_threshold: usize,                                        // 用于新创建的 tracker
    min_warning_severity: LeakSeverity, // 报告为 WARNING 的最低严重程度
    // 新增：组件输入连接映射
    // 组件实例名 -> { 端口名 -> [父组件中连接的信号] }
    component_input_connections: HashMap<VariableName, HashMap<String, Vec<VariableName>>>,
    /// Recursion depth for function analysis
    recursion_depth: usize,
    /// Cache for function analysis results: (Func Name, Arg Taints) -> (Return Taint, Leakage Map)
    function_cache:
        Rc<RefCell<HashMap<(String, Vec<TaintLevel>), (TaintLevel, HashMap<usize, usize>)>>>,
    /// Constant values for variables (Simple Constant Propagation)
    constants: HashMap<VariableName, num_bigint::BigInt>,
    /// Cache for component analysis results: (Template Name, Input Taints) -> (Input Leakages)
    component_cache:
        Rc<RefCell<HashMap<(String, Vec<(String, TaintLevel)>), Vec<(String, usize)>>>>,
}

impl PrivacyTaint {
    pub fn new() -> PrivacyTaint {
        PrivacyTaint {
            leakage_threshold: 8, // 默认值
            min_warning_severity: LeakSeverity::High,
            recursion_depth: 0,
            function_cache: Rc::new(RefCell::new(HashMap::new())),
            constants: HashMap::new(),
            component_cache: Rc::new(RefCell::new(HashMap::new())),

            ..Default::default()
        }
    }

    pub fn with_threshold(threshold: usize) -> PrivacyTaint {
        PrivacyTaint {
            leakage_threshold: threshold,
            min_warning_severity: LeakSeverity::High,
            recursion_depth: 0,
            function_cache: Rc::new(RefCell::new(HashMap::new())),
            constants: HashMap::new(),
            component_cache: Rc::new(RefCell::new(HashMap::new())),

            ..Default::default()
        }
    }

    pub fn with_min_severity(mut self, severity: LeakSeverity) -> Self {
        self.min_warning_severity = severity;
        self
    }

    pub fn min_warning_severity(&self) -> LeakSeverity {
        self.min_warning_severity
    }

    pub fn level(&self, name: &VariableName) -> TaintLevel {
        *self.levels.get(name).unwrap_or(&TaintLevel::Clean)
    }

    fn set_level(&mut self, name: &VariableName, level: TaintLevel) -> bool {
        let current = self.level(name);
        if current == level {
            return false;
        }
        let new_level = current.join(level);
        if new_level != current {
            self.levels.insert(name.clone(), new_level);
            true
        } else {
            false
        }
    }

    /// 设置污点等级
    fn set_level_direct(&mut self, name: &VariableName, level: TaintLevel) -> bool {
        let current = self.level(name);
        if current != level {
            self.levels.insert(name.clone(), level);
            true
        } else {
            false
        }
    }

    fn set_component_type(&mut self, name: &VariableName, ty: &str) {
        self.component_types.insert(name.clone(), ty.to_string());
    }

    fn component_type(&self, name: &VariableName) -> Option<&str> {
        self.component_types.get(name).map(|s| s.as_str())
    }

    fn set_component_cfg(&mut self, name: &VariableName, weak: &WeakCfgRef) {
        self.component_cfgs.insert(name.clone(), weak.clone());
    }

    fn component_cfg(&self, name: &VariableName) -> Option<&WeakCfgRef> {
        self.component_cfgs.get(name)
    }

    fn add_component_input(&mut self, name: &VariableName, level: TaintLevel) {
        let entry = self.component_inputs.entry(name.clone()).or_insert(TaintLevel::Clean);
        *entry = entry.join(level);
    }

    fn component_input_level(&self, name: &VariableName) -> TaintLevel {
        *self.component_inputs.get(name).unwrap_or(&TaintLevel::Clean)
    }

    fn add_component_port_level(&mut self, name: &VariableName, port: &str, level: TaintLevel) {
        let entry = self
            .component_port_levels
            .entry(name.clone())
            .or_insert_with(HashMap::new)
            .entry(port.to_string())
            .or_insert(TaintLevel::Clean);
        *entry = entry.join(level);
    }

    fn component_port_level(&self, name: &VariableName, port: &str) -> TaintLevel {
        self.component_port_levels
            .get(name)
            .and_then(|m| m.get(port))
            .copied()
            .unwrap_or(TaintLevel::Clean)
    }

    /// 为私有变量初始化泄露跟踪器，带有估计的熵
    fn init_leakage_tracker(&mut self, name: &VariableName, entropy_bits: usize) {
        self.leakage_trackers
            .insert(name.clone(), LeakageTracker::new(entropy_bits, self.leakage_threshold));
    }

    /// 记录一个泄露操作用于量化
    fn record_leakage(&mut self, name: &VariableName, op: LeakageOp, bits: usize) {
        if let Some(tracker) = self.leakage_trackers.get_mut(name) {
            tracker.add_leakage(op, bits);
        }
    }

    /// 获取变量的泄露严重程度
    fn get_leakage_severity(&self, name: &VariableName) -> Option<LeakSeverity> {
        self.leakage_trackers.get(name).and_then(|t| t.severity())
    }

    /// 获取泄露信息L(x), H(x), T(x)用于结果报告
    fn get_leakage_info(&self, name: &VariableName) -> Option<(usize, usize, usize)> {
        self.leakage_trackers.get(name).map(|t| (t.leaked_bits, t.entropy_bits, t.threshold()))
    }

    /// 记录组件输入端口连接的信号
    fn record_component_input_connection(
        &mut self,
        component: &VariableName,
        port: &str,
        signals: Vec<VariableName>,
    ) {
        self.component_input_connections
            .entry(component.clone())
            .or_insert_with(HashMap::new)
            .insert(port.to_string(), signals);
    }
}

fn eval_access_level(var: &VariableName, access: &[AccessType], env: &PrivacyTaint) -> TaintLevel {
    use TaintLevel::*;
    // 基础变量的基本等级
    let mut result = env.level(var);
    let mut is_component_output = false;
    for a in access {
        match a {
            AccessType::ArrayAccess(index) => {
                let idx_level = eval_expr_level(index, env);
                if matches!(idx_level, Tainted | PartialLeak) {
                    // 索引污染 → 结果为 Tainted
                    result = Tainted;
                } else {
                    // 索引干净，根据数组本体等级决定
                    if !is_component_output {
                        match result {
                            Tainted => result = Tainted,
                            PartialLeak => result = PartialLeak, // 更温和：保持 PartialLeak
                            _ => {}
                        }
                    }
                }
            }
            AccessType::ComponentAccess(port) => {
                //  第一步：先尝试基于组件类型的映射（不需要子 CFG）
                let component_type = env.component_type(var);

                if let Some(mapped_level) = map_component_output_taint(component_type, result) {
                    // 命中已知组件，直接使用映射结果，不需要检查子 CFG
                    result = mapped_level;
                    is_component_output = true;
                } else {
                    // 第二步：未命中已知组件，尝试检查子 CFG 并递归分析
                    let is_output_port = if let Some(weak) = env.component_cfg(var) {
                        if let Some(rc) = weak.upgrade() {
                            // 先收集所有输出信号名称，然后释放借用
                            let output_names: Vec<String> = {
                                let child_cfg = rc.borrow();
                                child_cfg.output_signals().map(|n| n.name().to_string()).collect()
                            };
                            output_names.iter().any(|name| name == port)
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if is_output_port {
                        // 有子 CFG 且是输出端口，递归分析
                        if let Some(weak) = env.component_cfg(var) {
                            if let Some(rc) = weak.upgrade() {
                                let child_cfg = rc.borrow();
                                let seed_level = env.component_input_level(var);
                                let mut seed = HashMap::new();
                                // 为每个输入信号准备初始污点等级
                                for in_name in child_cfg.input_signals() {
                                    // 尝试从组件端口级别记录中获取精确等级
                                    let port_level = env.component_port_level(var, in_name.name());
                                    let level = if !matches!(port_level, TaintLevel::Clean) {
                                        // 有端口级精确记录，优先使用
                                        port_level
                                    } else {
                                        // 回退到聚合输入等级
                                        seed_level
                                    };
                                    seed.insert(in_name.clone(), level);
                                }
                                // 检查缓存以避免重复计算
                                let cache_key = (child_cfg.name().to_string(), seed_level);
                                if let Some(cached) = env.child_cache.borrow().get(&cache_key) {
                                    result = *cached;
                                    is_component_output = true;
                                    continue;
                                }
                                let child_env =
                                    run_privacy_taint_with_seed(&child_cfg, &seed, None);
                                let mut out_level = TaintLevel::Clean;
                                for out_name in child_cfg.output_signals() {
                                    let child_out_level = child_env.level(out_name);
                                    trace!(
                                        "Child output signal {:?} has level {:?}",
                                        out_name,
                                        child_out_level
                                    );
                                    out_level = out_level.join(child_out_level);
                                }
                                trace!(
                                    "Final aggregated out_level for child CFG '{}': {:?}",
                                    child_cfg.name(),
                                    out_level
                                );
                                result = out_level;
                                // 更新缓存
                                env.child_cache.borrow_mut().insert(cache_key, out_level);
                                is_component_output = true;
                            }
                        }
                    } else {
                        // 无子 CFG 或不是输出端口，使用默认的 Tainted
                        result = if matches!(result, TaintLevel::Clean) {
                            TaintLevel::Clean
                        } else {
                            TaintLevel::Tainted
                        };
                    }
                }
            }
        }
    }
    result
}

fn normalize_name(name: &str) -> String {
    name.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_lowercase()
}

/// 尝试根据组件类型映射输出污点等级
/// 返回 Some(level) 表示命中已知组件，None 表示未命中（需要递归分析）
fn map_component_output_taint(ctype_opt: Option<&str>, input: TaintLevel) -> Option<TaintLevel> {
    use TaintLevel::*;
    let Some(ctype) = ctype_opt else { return None };
    let cname = normalize_name(ctype);

    // 各种不可逆函数 → 如果任何输入不是 Clean 则 Downgraded
    let non_invertible: HashSet<&str> = HashSet::from([
        "poseidon",
        "mimc7",
        "pedersen",
        "eddsa",
        "eddsaposeidon",
        "merkletreeinclusionproof",
        "smtverifier",
    ]);
    let cmp_partial: HashSet<&str> = HashSet::from(["lessthan", "greatereq"]);
    let cmp_tainted: HashSet<&str> = HashSet::from(["equal", "iszero"]);
    let bit_tainted: HashSet<&str> = HashSet::from(["num2bits", "bits2num", "point2bits"]);
    let bit_downgraded: HashSet<&str> = HashSet::from(["bits2point"]);
    let logic_tainted: HashSet<&str> = HashSet::from(["and", "or", "not", "mux"]);
    let arith_tainted: HashSet<&str> = HashSet::from(["add", "multimux"]);

    if non_invertible.contains(cname.as_str()) {
        return Some(if matches!(input, Clean) { Clean } else { Downgraded });
    }
    if cmp_partial.contains(cname.as_str()) {
        return Some(match input {
            Tainted | PartialLeak => PartialLeak,
            Downgraded => Downgraded,
            Clean => Clean,
        });
    }
    if cmp_tainted.contains(cname.as_str()) {
        return Some(match input {
            Tainted | PartialLeak => Tainted,
            Downgraded => Downgraded,
            Clean => Clean,
        });
    }
    if bit_tainted.contains(cname.as_str()) {
        return Some(if matches!(input, Clean) { Clean } else { Tainted });
    }
    if bit_downgraded.contains(cname.as_str()) {
        return Some(if matches!(input, Clean) { Clean } else { Downgraded });
    }
    if logic_tainted.contains(cname.as_str()) || arith_tainted.contains(cname.as_str()) {
        return Some(if matches!(input, Clean) { Clean } else { Tainted });
    }

    // 未命中任何已知组件，返回 None 表示需要递归分析
    None
}

/// 库组件的输入泄露规则
#[derive(Clone, Debug, PartialEq)]
enum ComponentLeakageRule {
    None,             // 无量化泄露（如哈希）
    FixedBits(usize), // 固定比特数（如比较 = 1 bit）
    LeakAll,          // 泄露全部输入熵（如 Num2Bits）
}

/// 为已知库组件返回输入泄露规则
/// 返回 Some(rule) 表示命中已知组件规则，None 表示未命中（需递归分析）
fn get_component_input_leakage_rule(
    component_type: &str,
    input_port: &str,
    _input_level: TaintLevel,
) -> Option<ComponentLeakageRule> {
    let cname = normalize_name(component_type);

    match cname.as_str() {
        // Num2Bits: 输入泄露所有位（取决于参数 n）
        "num2bits" if input_port == "in" => Some(ComponentLeakageRule::LeakAll),

        // LessThan, GreaterEq, LessEqThan, GreaterThan: 通过 Num2Bits 间接泄露
        "lessthan" | "greatereq" | "lesseqthan" | "greaterthan" if input_port == "in" => {
            Some(ComponentLeakageRule::LeakAll) // 内部调用 Num2Bits(n+1)
        }

        // IsEqual, IsZero: 比较类，泄露 1 bit
        "isequal" | "iszero" if input_port == "in" => Some(ComponentLeakageRule::FixedBits(1)),

        // 哈希类组件：无量化泄露（只是 Downgraded）
        "poseidon"
        | "mimc7"
        | "pedersen"
        | "eddsa"
        | "eddsaposeidon"
        | "merkletreeinclusionproof"
        | "smtverifier" => Some(ComponentLeakageRule::None),

        // 未知组件 → 需要递归分析
        _ => None,
    }
}

fn eval_infix(op: ExpressionInfixOpcode, lhs: TaintLevel, rhs: TaintLevel) -> TaintLevel {
    use ExpressionInfixOpcode::*;
    use TaintLevel::*;
    match op {
        ShiftL | ShiftR => {
            // 位移导致部分泄露；Downgraded 保持不升级
            match (lhs, rhs) {
                (Downgraded, _) | (_, Downgraded) => Downgraded,
                (Tainted, _) | (_, Tainted) => PartialLeak,
                (PartialLeak, _) | (_, PartialLeak) => PartialLeak,
                _ => PartialLeak,
            }
        }
        BitAnd => {
            // 特判 x & 1 为位提取
            if (matches!(lhs, Tainted | PartialLeak) && matches!(rhs, Clean | Downgraded))
                || (matches!(rhs, Tainted | PartialLeak) && matches!(lhs, Clean | Downgraded))
            {
                PartialLeak
            } else if matches!(lhs, Downgraded) || matches!(rhs, Downgraded) {
                Downgraded
            } else if matches!(lhs, Tainted | PartialLeak) || matches!(rhs, Tainted | PartialLeak) {
                PartialLeak
            } else {
                Clean
            }
        }
        // 其他算术与逻辑，任一输入泄露则输出为 Tainted；Downgraded 透传
        Mul | Div | Add | Sub | Pow | IntDiv | Mod | LesserEq | GreaterEq | Lesser | Greater
        | Eq | NotEq | BoolOr | BoolAnd | BitOr | BitXor => {
            if matches!(lhs, Tainted | PartialLeak) || matches!(rhs, Tainted | PartialLeak) {
                Tainted
            } else if matches!(lhs, Downgraded) || matches!(rhs, Downgraded) {
                Downgraded
            } else {
                Clean
            }
        }
    }
}

fn eval_prefix(op: ExpressionPrefixOpcode, rhs: TaintLevel) -> TaintLevel {
    use ExpressionPrefixOpcode::*;
    use TaintLevel::*;
    match op {
        BoolNot | Sub => {
            if matches!(rhs, Tainted | PartialLeak) {
                Tainted
            } else if matches!(rhs, Downgraded) {
                Downgraded
            } else {
                Clean
            }
        }
        Complement => {
            // 位级补码，按位操作视作部分泄露（若仅 Downgraded 则保持 Downgraded）
            if matches!(rhs, Downgraded) {
                Downgraded
            } else {
                PartialLeak
            }
        }
    }
}

fn analyze_function(
    target_cfg: &Cfg,
    args_taint: &[TaintLevel],
    parent_env: &PrivacyTaint,
) -> (TaintLevel, HashMap<usize, usize>) {
    // 0. Check Cache
    let func_key = (target_cfg.name().to_string(), args_taint.to_vec());
    if let Some(cached) = parent_env.function_cache.borrow().get(&func_key) {
        debug!("Cache hit for function: {}", target_cfg.name());
        return cached.clone();
    }

    // Prevent infinite recursion
    if parent_env.recursion_depth > 10 {
        return (TaintLevel::Tainted, HashMap::new());
    }

    // 1. Setup new env
    let mut func_env = PrivacyTaint::with_threshold(parent_env.leakage_threshold)
        .with_min_severity(parent_env.min_warning_severity);
    func_env.recursion_depth = parent_env.recursion_depth + 1;
    // Share the global function cache
    func_env.function_cache = parent_env.function_cache.clone();

    // 2. Initialize parameters
    // Function parameters are locals in the CFG, but parameters() gives their names
    for (i, param) in target_cfg.parameters().iter().enumerate() {
        if let Some(level) = args_taint.get(i) {
            func_env.set_level_direct(param, *level);
            // If the argument is tainted/partial, track leakage on the parameter
            if matches!(level, TaintLevel::Tainted | TaintLevel::PartialLeak) {
                // Initialize with entropy 254 (default assumption for signals)
                func_env.init_leakage_tracker(param, 254);
            }
        }
    }

    // 3. Run analysis loop (simplified fixed-point)
    // We only care about forward propagation
    let mut changed = true;
    let mut iter = 0;
    while changed && iter < 100 {
        changed = false;
        iter += 1;
        for bb in target_cfg.iter() {
            for stmt in bb.iter() {
                use Statement::*;
                match stmt {
                    Substitution { var, rhe, .. } => {
                        let rhs_level = eval_expr_level(rhe, &func_env);
                        changed = func_env.set_level(var, rhs_level) || changed;
                    }
                    Declaration { names, dimensions, .. } => {
                        let dim_level = dimensions.iter().fold(TaintLevel::Clean, |acc, e| {
                            acc.join(eval_expr_level(e, &func_env))
                        });
                        for name in names {
                            changed = func_env.set_level(name, dim_level) || changed;
                        }
                    }
                    IfThenElse { cond, .. } => {
                        let c = eval_expr_level(cond, &func_env);
                        if matches!(c, TaintLevel::Tainted | TaintLevel::PartialLeak) {
                            for sink in bb.variables_written() {
                                changed =
                                    func_env.set_level(sink.name(), TaintLevel::Tainted) || changed;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // 4. Run leakage tracking pass (Once)
    for bb in target_cfg.iter() {
        for stmt in bb.iter() {
            use Statement::*;
            match stmt {
                Substitution { rhe, .. } => {
                    track_expr_leakage(rhe, target_cfg, &mut func_env, None);
                }
                IfThenElse { cond, .. } => {
                    track_expr_leakage(cond, target_cfg, &mut func_env, None);
                }
                Return { value, .. } => {
                    track_expr_leakage(value, target_cfg, &mut func_env, None);
                }
                _ => {}
            }
        }
    }

    // 5. Collect leakage on parameters
    let mut leakage_map = HashMap::new();
    for (i, param) in target_cfg.parameters().iter().enumerate() {
        if let Some(tracker) = func_env.leakage_trackers.get(param) {
            if tracker.leaked_bits > 0 {
                leakage_map.insert(i, tracker.leaked_bits);
            }
        }
    }

    // 6. Get Return Value taint
    let mut return_level = TaintLevel::Clean;
    for bb in target_cfg.iter() {
        for stmt in bb.iter() {
            if let Statement::Return { value, .. } = stmt {
                return_level = return_level.join(eval_expr_level(value, &func_env));
            }
        }
    }

    let result = (return_level, leakage_map);
    // Cache the result
    parent_env.function_cache.borrow_mut().insert(func_key, result.clone());

    result
}

fn eval_expr_level(expr: &Expression, env: &PrivacyTaint) -> TaintLevel {
    use Expression::*;
    use TaintLevel::*;
    match expr {
        Number(_, _) => Clean,
        Variable { name, .. } => env.level(name),
        InfixOp { lhe, infix_op, rhe, .. } => {
            let lhs = eval_expr_level(lhe, env);
            let rhs = eval_expr_level(rhe, env);
            eval_infix(*infix_op, lhs, rhs)
        }
        PrefixOp { prefix_op, rhe, .. } => {
            let rhs = eval_expr_level(rhe, env);
            eval_prefix(*prefix_op, rhs)
        }
        SwitchOp { cond, if_true, if_false, .. } => {
            let c = eval_expr_level(cond, env);
            let a = eval_expr_level(if_true, env);
            let b = eval_expr_level(if_false, env);
            if matches!(c, Tainted | PartialLeak)
                || matches!(a, Tainted | PartialLeak)
                || matches!(b, Tainted | PartialLeak)
            {
                Tainted
            } else if matches!(c, Downgraded) || matches!(a, Downgraded) || matches!(b, Downgraded)
            {
                Downgraded
            } else {
                Clean
            }
        }
        InlineArray { values, .. } => {
            values.iter().fold(Clean, |acc, v| acc.join(eval_expr_level(v, env)))
        }
        Access { var, access, .. } => eval_access_level(var, access, env),
        Update { var, access, rhe, .. } => {
            let base = eval_access_level(var, access, env);
            base.join(eval_expr_level(rhe, env))
        }
        Call { args, target_cfg, .. } => {
            let levels = args.iter().map(|a| eval_expr_level(a, env)).collect::<Vec<_>>();

            // 尝试使用分析函数深入分析
            if let Some(weak_ref) = target_cfg {
                if let Some(cfg_rc) = weak_ref.upgrade() {
                    let cfg = cfg_rc.borrow();
                    if matches!(
                        cfg.definition_type(),
                        program_structure::cfg::DefinitionType::Function
                    ) {
                        let (ret_level, _) = analyze_function(&cfg, &levels, env);
                        return ret_level;
                    }
                }
            }

            if levels.iter().any(|l| matches!(l, Tainted | PartialLeak)) {
                Tainted
            } else if levels.iter().any(|l| matches!(l, Downgraded)) {
                Downgraded
            } else {
                Clean
            }
        }
        Phi { args, .. } => args.iter().fold(Clean, |acc, name| acc.join(env.level(name))),
    }
}

enum LoopResolution {
    KnownBound(usize),
    UnknownBound,
    NotLoop,
}

/// Detects if a variable is likely a loop variable and attempts to infer its upper bound.
fn detect_loop_variable_bound(
    var_name: &VariableName,
    cfg: &Cfg,
    constants: &HashMap<VariableName, num_bigint::BigInt>,
    ctx: Option<&dyn AnalysisContext>,
) -> LoopResolution {
    let base_name = var_name.name();
    let mut initialized_to_zero = false;
    let mut upper_bound = None;

    // Track definition meta for source lookup
    let mut def_meta: Option<program_structure::ir::Meta> = None;

    // Scan CFG
    for bb in cfg.iter() {
        for stmt in bb.iter() {
            // Check initialization: var.0 = 0
            if let Statement::Substitution { var, rhe, meta, .. } = stmt {
                if var.name() == base_name && *var.version() == Some(0) {
                    if let Expression::Number(_, val) = rhe {
                        if val == &num_bigint::BigInt::from(0) {
                            initialized_to_zero = true;
                            def_meta = Some(meta.clone());
                        }
                    }
                }
            }

            match stmt {
                Statement::Substitution { rhe, .. }
                | Statement::ConstraintEquality { lhe: rhe, .. } => {
                    // Check InfixOp
                    if let Expression::InfixOp { lhe, infix_op, rhe: right, .. } = rhe {
                        let lhs_is_var = if let Expression::Variable { name, .. } = &**lhe {
                            name.name() == base_name
                        } else {
                            false
                        };
                        if lhs_is_var {
                            // Helper to resolve bound value (literal or constant var)
                            let resolve_bound = |expr: &Expression| -> Option<usize> {
                                match expr {
                                    Expression::Number(_, val) => val.to_string().parse::<usize>().ok(),
                                    Expression::Variable { name, .. } => {
                                        constants.get(name).and_then(|val| val.to_string().parse::<usize>().ok())
                                    }
                                    _ => None,
                                }
                            };

                            match infix_op {
                                ExpressionInfixOpcode::Lesser => {
                                    if let Some(c) = resolve_bound(&**right) {
                                        upper_bound = Some(c);
                                    }
                                }
                                ExpressionInfixOpcode::LesserEq => {
                                    if let Some(c) = resolve_bound(&**right) {
                                        upper_bound = Some(c + 1);
                                    }
                                }
                                ExpressionInfixOpcode::NotEq => {
                                    if let Some(c) = resolve_bound(&**right) {
                                        upper_bound = Some(c);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if initialized_to_zero {
        if let Some(bound) = upper_bound {
            debug!("Detected loop variable '{}' with bound {}", base_name, bound);
            return LoopResolution::KnownBound(bound);
        } else {
            // Fallback: Try to infer from source code
            if let Some(c) = ctx {
                if let Some(meta) = def_meta {
                    if let Some(bound) = infer_bound_from_source(&meta, c, base_name) {
                        debug!(
                            "Inferred bound {} from source code for loop variable {}",
                            bound, base_name
                        );
                        return LoopResolution::KnownBound(bound);
                    }
                }
            }

            debug!("Detected loop variable '{}' but bound unknown", base_name);
            return LoopResolution::UnknownBound;
        }
    }

    LoopResolution::NotLoop
}

fn infer_bound_from_source(
    meta: &program_structure::ir::Meta,
    ctx: &dyn AnalysisContext,
    var_name: &str,
) -> Option<usize> {
    // meta.file_id is expected to be valid
    if let Some(file_id) = meta.file_id {
        // Read a window after the definition
        let start = meta.location.end;
        let end = start + 128; // Lookahead 128 chars
        let range = start..end;

        // We handle potential out-of-bounds by context returning Err (hopefully)
        // or we try smaller windows? context.underlying_str should check bounds.
        // But if file is smaller than start+128, it errors.
        // We don't know file size.
        // But we can try to get whatever string we can? No API for that.
        // We assume file is large enough or accept failure.

        if let Ok(slice) = ctx.underlying_str(&file_id, &range) {
            // We expect pattern like: "; i < 8;"
            // Check for next semicolon (end of init)
            let sc_idx = slice.find(';')?;
            // Condition starts after this semicolon
            let cond_start = sc_idx + 1;
            if cond_start >= slice.len() {
                return None;
            }

            let slice_after_init = &slice[cond_start..];
            // Condition ends at next semicolon
            let sc_end = slice_after_init.find(';')?;
            let cond_str = &slice_after_init[..sc_end];

            // Check if contains variable and '<'
            if !cond_str.contains(var_name) || !cond_str.contains('<') {
                return None;
            }

            // Split by '<', take second part
            let parts: Vec<&str> = cond_str.split('<').collect();
            if parts.len() < 2 {
                return None;
            }
            let rhs = parts[1].trim();

            // Parse number. Take digits.
            let num_str: String = rhs.chars().take_while(|c| c.is_ascii_digit()).collect();
            return num_str.parse::<usize>().ok();
        }
    }
    None
}

/// 递归折叠表达式中的常量变量
/// 将所有在常量表中的变量替换为对应的常量值
fn constant_fold_expression(
    expr: &Expression,
    constants: &HashMap<VariableName, num_bigint::BigInt>,
) -> Expression {
    use Expression::*;

    match expr {
        // 变量：如果在常量表中，替换为常量
        Variable { name, meta } => {
            // 先尝试精确匹配（包含版本号）
            if let Some(value) = constants.get(name) {
                debug!("Folding variable {:?} to constant {}", name, value);
                return Number(meta.clone(), value.clone());
            }

            // 如果精确匹配失败，尝试匹配无版本号的变量
            // 这对于 SSA 转换后的循环变量很重要（如 i.0, i.1, i.2 -> i）
            if name.version().is_some() {
                let name_without_version = name.without_version();
                if let Some(value) = constants.get(&name_without_version) {
                    debug!(
                        "Folding versioned variable {:?} (base: {:?}) to constant {}",
                        name, name_without_version, value
                    );
                    return Number(meta.clone(), value.clone());
                }
            }

            expr.clone()
        }

        // 中缀操作：递归折叠左右操作数
        InfixOp { lhe, infix_op, rhe, meta } => {
            let folded_lhe = constant_fold_expression(lhe, constants);
            let folded_rhe = constant_fold_expression(rhe, constants);
            InfixOp {
                lhe: Box::new(folded_lhe),
                infix_op: *infix_op,
                rhe: Box::new(folded_rhe),
                meta: meta.clone(),
            }
        }

        // 前缀操作：递归折叠操作数
        PrefixOp { prefix_op, rhe, meta } => {
            let folded_rhe = constant_fold_expression(rhe, constants);
            PrefixOp { prefix_op: *prefix_op, rhe: Box::new(folded_rhe), meta: meta.clone() }
        }

        // Switch 操作：递归折叠所有分支
        SwitchOp { cond, if_true, if_false, meta } => {
            let folded_cond = constant_fold_expression(cond, constants);
            let folded_true = constant_fold_expression(if_true, constants);
            let folded_false = constant_fold_expression(if_false, constants);
            SwitchOp {
                cond: Box::new(folded_cond),
                if_true: Box::new(folded_true),
                if_false: Box::new(folded_false),
                meta: meta.clone(),
            }
        }

        // InlineArray: 递归折叠数组中的每个元素
        InlineArray { values, meta } => {
            let folded_values: Vec<Expression> =
                values.iter().map(|v| constant_fold_expression(v, constants)).collect();
            InlineArray { values: folded_values, meta: meta.clone() }
        }

        // Access: 递归折叠访问索引
        Access { var, access, meta } => {
            let folded_access: Vec<AccessType> = access
                .iter()
                .map(|a| match a {
                    AccessType::ArrayAccess(idx_expr) => AccessType::ArrayAccess(Box::new(
                        constant_fold_expression(idx_expr, constants),
                    )),
                    other => other.clone(),
                })
                .collect();
            Access { var: var.clone(), access: folded_access, meta: meta.clone() }
        }

        // Update: 递归折叠访问索引和右侧表达式
        Update { var, access, rhe, meta } => {
            let folded_access: Vec<AccessType> = access
                .iter()
                .map(|a| match a {
                    AccessType::ArrayAccess(idx_expr) => AccessType::ArrayAccess(Box::new(
                        constant_fold_expression(idx_expr, constants),
                    )),
                    other => other.clone(),
                })
                .collect();
            let folded_rhe = constant_fold_expression(rhe, constants);
            Update {
                var: var.clone(),
                access: folded_access,
                rhe: Box::new(folded_rhe),
                meta: meta.clone(),
            }
        }

        // Call: 递归折叠参数
        Call { name, args, meta, target_cfg } => {
            let folded_args: Vec<Expression> =
                args.iter().map(|arg| constant_fold_expression(arg, constants)).collect();
            Call {
                name: name.clone(),
                args: folded_args,
                meta: meta.clone(),
                target_cfg: target_cfg.clone(),
            }
        }

        // 其他类型（Number, Phi）直接返回
        _ => expr.clone(),
    }
}

/// 从表达式中提取所有信号变量名（用于追踪组件输入连接）
fn extract_signal_names(expr: &Expression) -> Vec<VariableName> {
    use Expression::*;
    let mut result = Vec::new();

    match expr {
        Variable { name, .. } => {
            result.push(name.clone());
        }
        Access { var, .. } => {
            result.push(var.clone());
        }
        InfixOp { lhe, rhe, .. } => {
            result.extend(extract_signal_names(lhe));
            result.extend(extract_signal_names(rhe));
        }
        PrefixOp { rhe, .. } => {
            result.extend(extract_signal_names(rhe));
        }
        SwitchOp { cond, if_true, if_false, .. } => {
            result.extend(extract_signal_names(cond));
            result.extend(extract_signal_names(if_true));
            result.extend(extract_signal_names(if_false));
        }
        InlineArray { values, .. } => {
            for v in values {
                result.extend(extract_signal_names(v));
            }
        }
        Update { var, rhe, .. } => {
            result.push(var.clone());
            result.extend(extract_signal_names(rhe));
        }
        Call { args, .. } => {
            for arg in args {
                result.extend(extract_signal_names(arg));
            }
        }
        Phi { args, .. } => {
            result.extend(args.clone());
        }
        Number(..) => {}
    }

    result
}

/// 递归查找表达式中使用的所有私有输入信号名称
fn find_private_inputs_in_expr(
    expr: &Expression,
    env: &PrivacyTaint,
    result: &mut Vec<VariableName>,
) {
    use Expression::*;
    match expr {
        Variable { name, .. } => {
            if env.level(name) == TaintLevel::Tainted && !result.contains(name) {
                result.push(name.clone());
            }
        }
        InfixOp { lhe, rhe, .. } => {
            find_private_inputs_in_expr(lhe, env, result);
            find_private_inputs_in_expr(rhe, env, result);
        }
        PrefixOp { rhe, .. } => {
            find_private_inputs_in_expr(rhe, env, result);
        }
        SwitchOp { cond, if_true, if_false, .. } => {
            find_private_inputs_in_expr(cond, env, result);
            find_private_inputs_in_expr(if_true, env, result);
            find_private_inputs_in_expr(if_false, env, result);
        }
        Access { var, .. } => {
            if env.level(var) == TaintLevel::Tainted && !result.contains(var) {
                result.push(var.clone());
            }
        }
        _ => {}
    }
}

/// 分析表达式并跟踪泄露操作（修改 env）
/// 当结果用于公共上下文时调用  
fn track_expr_leakage(
    expr: &Expression,
    cfg: &Cfg,
    env: &mut PrivacyTaint,
    ctx: Option<&dyn AnalysisContext>,
) {
    use Expression::*;
    use ExpressionInfixOpcode::*;

    // 查找此表达式中涉及的所有私有输入
    let mut private_inputs = Vec::new();
    find_private_inputs_in_expr(expr, env, &mut private_inputs);

    match expr {
        // 位提取：x & C（掩码提取）
        // 也处理 (x >> N) & C 模式
        InfixOp { lhe, infix_op: BitAnd, rhe, .. } => {
            // 检查是否有一边是常量
            let (expr_side, const_side) = match (&**lhe, &**rhe) {
                (Number(_, val), other) | (other, Number(_, val)) => (Some(other), Some(val)),
                _ => (None, None),
            };

            if let (Some(expr_side), Some(mask_val)) = (expr_side, const_side) {
                // 计算掩码中的 1 的位数 (popcount)
                let mask_str = mask_val.to_string();
                let leaked_bits_count = if let Ok(n) = mask_str.parse::<u128>() {
                    n.count_ones() as usize
                } else if let Some(_n) = num_bigint::BigInt::parse_bytes(mask_str.as_bytes(), 10) {
                    // 对于大整数，简单处理（通常不会很大用于掩码）
                    // 这里简化处理：如果是大数掩码，假设泄露所有位（或者不做量化，只标记 taint）
                    // 为简单起见，这里只处理 u128 范围内的掩码，超出范围的暂忽略量化或设为 High
                    64 // 启发式最大值
                } else {
                    0
                };

                if leaked_bits_count > 0 {
                    // 检查 expr_side 是否是移位操作：(secret >> N)
                    if let InfixOp {
                        lhe: shift_lhe,
                        infix_op: ShiftR | ShiftL,
                        rhe: shift_rhe,
                        ..
                    } = expr_side
                    {
                        // (secret >> N) & mask
                        let mut shift_private_inputs = Vec::new();
                        find_private_inputs_in_expr(shift_lhe, env, &mut shift_private_inputs);

                        if let Number(_, shift_val) = &**shift_rhe {
                            // 记录特定索引处的位提取
                            if let Ok(shift_amt) = shift_val.to_string().parse::<usize>() {
                                for secret_name in &shift_private_inputs {
                                    let op = LeakageOp::BitExtract {
                                        secret: secret_name.to_string(),
                                        bit_index: shift_amt, // 这里简化：记录起始位，虽然是多位提取
                                    };
                                    // 记录 popcount(mask) 个比特的泄露
                                    env.record_leakage(secret_name, op, leaked_bits_count);
                                    debug!(
                                        "Recorded bitmask: ({} >> {}) & {} ({} bits leaked)",
                                        secret_name, shift_amt, mask_val, leaked_bits_count
                                    );
                                }
                                return;
                            }
                        }

                        // 处理非常量移位的情况（例如在循环中使用变量 `i` 作为移位量）
                        // 【关键改进】：使用循环模式识别替代固定启发式
                        if let Variable { name: shift_var_name, .. } = &**shift_rhe {
                            // Check for Constant Propagation first
                            if let Some(const_val) = env.constants.get(shift_var_name) {
                                if let Ok(shift_amt) = const_val.to_string().parse::<usize>() {
                                    for secret_name in &shift_private_inputs {
                                        let op = LeakageOp::BitExtract {
                                            secret: secret_name.to_string(),
                                            bit_index: shift_amt,
                                        };
                                        env.record_leakage(secret_name, op, leaked_bits_count);
                                        debug!("Recorded bitmask (const prop): ({} >> {}) & {} ({} bits leaked)", 
                                               secret_name, shift_amt, mask_val, leaked_bits_count);
                                    }
                                    return;
                                }
                            }

                            for secret_name in &shift_private_inputs {
                                // Check if it's a loop variable with known bound
                                match detect_loop_variable_bound(shift_var_name, cfg, &env.constants, ctx) {
                                    LoopResolution::KnownBound(loop_bound) => {
                                        // Successfully identified loop variable and bound
                                        debug!(
                                            "Detected loop variable {} with bound {}",
                                            shift_var_name.name(),
                                            loop_bound
                                        );

                                        // For each possible iteration (0..bound), create a bit extract leakage op
                                        for i in 0..loop_bound {
                                            let op = LeakageOp::BitExtract {
                                                secret: secret_name.to_string(),
                                                bit_index: i,
                                            };
                                            // Leakage is 1 bit per iteration (assuming & 1)
                                            env.record_leakage(secret_name, op, leaked_bits_count);
                                        }

                                        debug!("Recorded {} loop iterations: ({} >> 0..{}) & {} ({} bits each)",
                                               loop_bound, secret_name, loop_bound, mask_val, leaked_bits_count);
                                    }
                                    LoopResolution::UnknownBound => {
                                        // Detected loop but unknown bound
                                        let max_entropy = env
                                            .leakage_trackers
                                            .get(secret_name)
                                            .map(|t| t.entropy_bits)
                                            .unwrap_or(254);

                                        let op = LeakageOp::VariableBitExtract {
                                            secret: secret_name.to_string(),
                                        };
                                        env.record_leakage(secret_name, op, max_entropy);
                                        debug!("Recorded variable bit extraction (unknown loop bound): ({} >> {}) & {} ({} bits, max entropy)",
                                               secret_name, shift_var_name.name(), mask_val, max_entropy);
                                    }
                                    LoopResolution::NotLoop => {
                                        // Failed to identify as loop pattern
                                        let max_entropy = env
                                            .leakage_trackers
                                            .get(secret_name)
                                            .map(|t| t.entropy_bits)
                                            .unwrap_or(254);

                                        let op = LeakageOp::VariableBitExtract {
                                            secret: secret_name.to_string(),
                                        };
                                        env.record_leakage(secret_name, op, max_entropy);

                                        debug!("Recorded variable bit extraction (unknown pattern): ({} >> {}) & {} ({} bits, max entropy)",
                                               secret_name, shift_var_name.name(), mask_val, max_entropy);
                                    }
                                }
                            }
                        } else {
                            // shift_rhe 既不是 Number 也不是 Variable，可能是复杂表达式
                            // 使用保守估计
                            for secret_name in &shift_private_inputs {
                                let max_entropy = env
                                    .leakage_trackers
                                    .get(secret_name)
                                    .map(|t| t.entropy_bits)
                                    .unwrap_or(254);

                                let op = LeakageOp::VariableBitExtract {
                                    secret: secret_name.to_string(),
                                };
                                env.record_leakage(secret_name, op, max_entropy);

                                debug!("Recorded complex shift expression: {} >> ? & {} ({} bits, max entropy)",
                                       secret_name, mask_val, max_entropy);
                            }
                        }
                        return;
                    } else {
                        // 变量 & mask
                        for secret_name in &private_inputs {
                            let op = LeakageOp::BitExtract {
                                secret: secret_name.to_string(),
                                bit_index: 0,
                            };
                            env.record_leakage(secret_name, op, leaked_bits_count);
                            debug!(
                                "Recorded bitmask: {} & {} ({} bits leaked)",
                                secret_name, mask_val, leaked_bits_count
                            );
                        }
                        return;
                    }
                }
            }

            // 回退：递归到两边
            track_expr_leakage(lhe, cfg, env, ctx);
            track_expr_leakage(rhe, cfg, env, ctx);
        }

        // 位运算 OR：x | m
        // 泄露量 = m 中为 0 的位数 (即保留的位)
        InfixOp { lhe, infix_op: BitOr, rhe, .. } => {
            let (expr_side, const_side) = match (&**lhe, &**rhe) {
                (Number(_, val), other) | (other, Number(_, val)) => (Some(other), Some(val)),
                _ => (None, None),
            };

            if let (Some(_), Some(mask_val)) = (expr_side, const_side) {
                let mask_str = mask_val.to_string();
                // 默认 254 bits 宽度的域
                let total_width: usize = 254;
                let ones_count = if let Ok(n) = mask_str.parse::<u128>() {
                    n.count_ones() as usize
                } else if let Some(_n) = num_bigint::BigInt::parse_bytes(mask_str.as_bytes(), 10) {
                    // 大数处理
                    64 // 启发式
                } else {
                    0
                };

                // 泄露的是 mask 为 0 的位
                let leaked_bits_count = total_width.saturating_sub(ones_count);

                for secret_name in &private_inputs {
                    // 使用 bit_index: 0 作为通用位操作的占位符去重键
                    let op =
                        LeakageOp::BitExtract { secret: secret_name.to_string(), bit_index: 0 };
                    env.record_leakage(secret_name, op, leaked_bits_count);
                    debug!(
                        "Recorded BitOr: {} | {} ({} bits leaked)",
                        secret_name, mask_val, leaked_bits_count
                    );
                }
            }
            // 递归
            track_expr_leakage(lhe, cfg, env, ctx);
            track_expr_leakage(rhe, cfg, env, ctx);
        }

        // 比较操作：泄露 1 比特
        InfixOp { lhe, infix_op, rhe, .. }
            if matches!(infix_op, Eq | NotEq | Lesser | Greater | LesserEq | GreaterEq) =>
        {
            // 规范化逻辑：确保 (secret op constant) 结构
            // 如果是 (constant op secret)，则翻转操作符
            let (normalized_op, constant_val) = match (&**lhe, &**rhe) {
                (Number(_, val), _) => {
                    // LHS 是常数：10 > x  -->  x < 10
                    let flipped_op = match infix_op {
                        Eq => "Eq",
                        NotEq => "NotEq",
                        Lesser => "Gt",    // 10 < x => x > 10
                        Greater => "Lt",   // 10 > x => x < 10
                        LesserEq => "Ge",  // 10 <= x => x >= 10
                        GreaterEq => "Le", // 10 >= x => x <= 10
                        _ => "Unknown",
                    };
                    (flipped_op, Some(val.to_string()))
                }
                (_, Number(_, val)) => {
                    // RHS 是常数：x < 10 (保持不变)
                    let op_str = match infix_op {
                        Eq => "Eq",
                        NotEq => "NotEq",
                        Lesser => "Lt",
                        Greater => "Gt",
                        LesserEq => "Le",
                        GreaterEq => "Ge",
                        _ => "Unknown",
                    };
                    (op_str, Some(val.to_string()))
                }
                _ => {
                    // 变量间比较
                    let op_str = match infix_op {
                        Eq => "Eq",
                        NotEq => "NotEq",
                        Lesser => "Lt",
                        Greater => "Gt",
                        LesserEq => "Le",
                        GreaterEq => "Ge",
                        _ => "Unknown",
                    };
                    (op_str, None)
                }
            };

            for secret_name in &private_inputs {
                let op = LeakageOp::Comparison {
                    secret: secret_name.to_string(),
                    op: normalized_op.to_string(),
                    constant: constant_val.clone(),
                };
                env.record_leakage(secret_name, op, 1); // 比较泄露 1 比特
            }

            track_expr_leakage(lhe, cfg, env, ctx);
            track_expr_leakage(rhe, cfg, env, ctx);
        }

        // 移位操作：本身不是泄露
        // 只有与位提取组合时（在上面的 BitAnd 情况中处理）
        // TODO 或者公开了移位后剩下的高位
        // 移位操作：y = x >> N
        // 如果结果被公开，泄露 High Bits (High = Total - N)
        InfixOp { lhe, infix_op: ShiftR, rhe, .. } => {
            if let Number(_, shift_val) = &**rhe {
                if let Ok(shift_amt) = shift_val.to_string().parse::<usize>() {
                    for secret_name in &private_inputs {
                        // 获取该 secret 的熵，如果不知则默认为 254
                        let entropy = env
                            .leakage_trackers
                            .get(secret_name)
                            .map(|t| t.entropy_bits)
                            .unwrap_or(254);
                        let leaked_count = entropy.saturating_sub(shift_amt);

                        if leaked_count > 0 {
                            // 使用 bit_index 来区分不同的移位
                            let op = LeakageOp::BitExtract {
                                secret: secret_name.to_string(),
                                bit_index: shift_amt,
                            };
                            env.record_leakage(secret_name, op, leaked_count);
                            debug!(
                                "Recorded ShiftR: {} >> {} ({} bits leaked)",
                                secret_name, shift_amt, leaked_count
                            );
                        }
                    }
                }
            }
            // 递归
            track_expr_leakage(lhe, cfg, env, ctx);
            track_expr_leakage(rhe, cfg, env, ctx);
        }

        InfixOp { lhe, rhe, .. } => {
            track_expr_leakage(lhe, cfg, env, ctx);
            track_expr_leakage(rhe, cfg, env, ctx);
        }
        PrefixOp { rhe, .. } => {
            track_expr_leakage(rhe, cfg, env, ctx);
        }
        Variable { .. } | Number(..) => {}
        Call { name, args, target_cfg, .. } => {
            // 递归检查参数
            for arg in args {
                track_expr_leakage(arg, cfg, env, ctx);
            }

            // 分析函数内部泄露
            if let Some(weak_ref) = target_cfg {
                if let Some(cfg_rc) = weak_ref.upgrade() {
                    let func_cfg = cfg_rc.borrow();
                    if matches!(
                        func_cfg.definition_type(),
                        program_structure::cfg::DefinitionType::Function
                    ) {
                        // 准备参数污点等级
                        let arg_levels: Vec<TaintLevel> =
                            args.iter().map(|a| eval_expr_level(a, env)).collect();
                        // 分析
                        let (_, leakage_map) = analyze_function(&func_cfg, &arg_levels, env);

                        // 回溯泄露
                        for (arg_idx, leak_bits) in leakage_map {
                            if let Some(arg_expr) = args.get(arg_idx) {
                                // 如果 arg 是变量
                                if let Variable { name: arg_name, .. } = arg_expr {
                                    let op =
                                        LeakageOp::FunctionCall { function_name: name.clone() };
                                    env.record_leakage(arg_name, op, leak_bits);
                                }
                                // 如果 arg 是数组访问 (arr[i])，我们也应该记录
                                else if let Access { var: arg_name, .. } = arg_expr {
                                    // 简单归咎于数组变量
                                    let op =
                                        LeakageOp::FunctionCall { function_name: name.clone() };
                                    env.record_leakage(arg_name, op, leak_bits);
                                }
                            }
                        }
                    }
                }
            }
        }
        Access { .. } | Update { .. } | SwitchOp { .. } | InlineArray { .. } | Phi { .. } => {
            // 简单递归
            match expr {
                Access { var: _, access, .. } => {
                    for a in access {
                        if let AccessType::ArrayAccess(e) = a {
                            track_expr_leakage(e, cfg, env, ctx);
                        }
                    }
                }
                Update { access, rhe, .. } => {
                    for a in access {
                        if let AccessType::ArrayAccess(e) = a {
                            track_expr_leakage(e, cfg, env, ctx);
                        }
                    }
                    track_expr_leakage(rhe, cfg, env, ctx);
                }
                SwitchOp { cond, if_true, if_false, .. } => {
                    track_expr_leakage(cond, cfg, env, ctx);
                    track_expr_leakage(if_true, cfg, env, ctx);
                    track_expr_leakage(if_false, cfg, env, ctx);
                }
                InlineArray { values, .. } => {
                    for v in values {
                        track_expr_leakage(v, cfg, env, ctx);
                    }
                }
                _ => {}
            }
        }
    }
}

pub fn run_privacy_taint(cfg: &Cfg, threshold: usize, min_severity: LeakSeverity) -> PrivacyTaint {
    run_privacy_taint_with_ctx(cfg, None, threshold, min_severity)
}

pub fn run_privacy_taint_with_ctx(
    cfg: &Cfg,
    ctx: Option<&dyn AnalysisContext>,
    threshold: usize,
    min_severity: LeakSeverity,
) -> PrivacyTaint {
    debug!("running privacy taint level analysis");
    let mut env = PrivacyTaint::with_threshold(threshold).with_min_severity(min_severity);
    run_privacy_taint_on_env(cfg, &HashMap::new(), &mut env, ctx);
    env
}

fn create_child_env(parent: &PrivacyTaint) -> PrivacyTaint {
    let mut child = PrivacyTaint::new();
    child.function_cache = parent.function_cache.clone();
    child.component_cache = parent.component_cache.clone();
    child.leakage_threshold = parent.leakage_threshold;
    child.min_warning_severity = parent.min_warning_severity;
    child.recursion_depth = parent.recursion_depth + 1;
    child
}

pub fn run_privacy_taint_with_seed(
    cfg: &Cfg,
    seed: &HashMap<VariableName, TaintLevel>,
    ctx: Option<&dyn AnalysisContext>,
) -> PrivacyTaint {
    let mut env = PrivacyTaint::new();
    run_privacy_taint_on_env(cfg, seed, &mut env, ctx);
    env
}

pub fn run_privacy_taint_on_env(
    cfg: &Cfg,
    seed: &HashMap<VariableName, TaintLevel>,
    env: &mut PrivacyTaint,
    ctx: Option<&dyn AnalysisContext>,
) {
    // 种子私有输入
    for name in cfg.private_input_signals() {
        env.set_level(name, TaintLevel::Tainted);
        env.init_leakage_tracker(name, 254);
    }
    // 种子提供的输入映射
    // 种子提供的输入映射
    for (name, level) in seed {
        env.set_level(name, *level);
        // 如果输入被污染，初始化泄露跟踪器
        if matches!(level, TaintLevel::Tainted | TaintLevel::PartialLeak) {
            env.init_leakage_tracker(name, 254);
        }
    }
    // 预扫描组件类型与子 CFG：记录 var = TemplateName(...) 的组件实例，并链接到子CFG
    // 同时进行简单的常量传播扫描 (0.5 Step)
    for bb in cfg.iter() {
        for stmt in bb.iter() {
            if let Statement::Substitution { var, rhe, .. } = stmt {
                if let Expression::Number(_, val) = rhe {
                    env.constants.insert(var.clone(), val.clone());
                    trace!("Identified constant: {:?} = {}", var, val);
                }
            }

            if let Statement::Substitution { meta, var, rhe, .. } = stmt {
                if let Some(vtype) = meta.type_knowledge().variable_type() {
                    if matches!(
                        vtype,
                        program_structure::ir::VariableType::Component
                            | program_structure::ir::VariableType::AnonymousComponent
                    ) {
                        if let Expression::Call { name, target_cfg, .. } = rhe {
                            env.set_component_type(var, name);
                            if let Some(weak) = target_cfg {
                                env.set_component_cfg(var, weak);
                            }
                        }
                    }
                }
                // 聚合组件输入：识别 `update(var, access, expr)` 且 access 含 `ComponentAccess`
                if let Expression::Update { var: uvar, access, rhe: inner, .. } = rhe {
                    // 检查是否是组件端口连接
                    for a in access {
                        if let AccessType::ComponentAccess(port) = a {
                            if uvar == var {
                                // 传播组件类型（处理 SSA 变量版本）
                                if let Some(ty) = env.component_type(uvar).map(|s| s.to_string()) {
                                    env.set_component_type(var, &ty);
                                }

                                // 这是组件端口连接（如 component.port <== expr）
                                let level = eval_expr_level(inner, &env);
                                env.add_component_input(var, level);
                                env.add_component_port_level(var, port, level);

                                // 新增：提取并记录连接的信号
                                let connected_signals = extract_signal_names(inner);
                                if !connected_signals.is_empty() {
                                    debug!(
                                        "Recording component input connection: {:?}.{} <== {:?}",
                                        var, port, connected_signals
                                    );
                                    env.record_component_input_connection(
                                        var,
                                        port,
                                        connected_signals,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let mut changed = true;
    let mut iter = 0usize;
    while changed && iter < 256 {
        changed = false;
        iter += 1;
        for bb in cfg.iter() {
            for stmt in bb.iter() {
                use Statement::*;
                match stmt {
                    Substitution { var, rhe, .. } => {
                        let rhs_level = eval_expr_level(rhe, &env);
                        changed = env.set_level(var, rhs_level) || changed;
                    }
                    Declaration { names, dimensions, .. } => {
                        let dim_level = dimensions
                            .iter()
                            .fold(TaintLevel::Clean, |acc, e| acc.join(eval_expr_level(e, &env)));
                        for name in names {
                            changed = env.set_level(name, dim_level) || changed;
                        }
                    }
                    IfThenElse { cond, .. } => {
                        let c = eval_expr_level(cond, &env);
                        if matches!(c, TaintLevel::Tainted | TaintLevel::PartialLeak) {
                            for sink in bb.variables_written() {
                                changed =
                                    env.set_level(sink.name(), TaintLevel::Tainted) || changed;
                            }
                        }
                    }
                    ConstraintEquality { .. } | Return { .. } | LogCall { .. } | Assert { .. } => {}
                }
            }
        }
    }
    // 2.5) 内部泄露跟踪 (Expression Leakage)
    for bb in cfg.iter() {
        for stmt in bb.iter() {
            match stmt {
                Statement::Substitution { var: _v, rhe, .. } => {
                    track_expr_leakage(rhe, cfg, env, ctx);
                    if let Expression::Update { rhe: update_rhe, .. } = rhe {
                        track_expr_leakage(update_rhe, cfg, env, ctx);
                    }
                }
                Statement::ConstraintEquality { lhe, rhe, .. } => {
                    track_expr_leakage(lhe, cfg, env, ctx);
                    track_expr_leakage(rhe, cfg, env, ctx);
                }
                _ => {}
            }
        }
    }

    // 3) 回溯子组件泄露到父组件信号
    debug!("Step 3: Back-propagating component leakage to parent signals (recursive)");
    for bb in cfg.iter() {
        for stmt in bb.iter() {
            if let Statement::Substitution { var, .. } = stmt {
                // 检查是否是组件变量（通过预扫描建立的映射）
                if let Some(component_type_str) = env.component_type(var).map(|s| s.to_string()) {
                    // 获取组件的所有输入端口连接
                    if let Some(port_connections) =
                        env.component_input_connections.get(var).cloned()
                    {
                        for (port, connected_signals) in port_connections.into_iter() {
                            let port: String = port;

                            // 分支 A：尝试库组件规则
                            let parent_signal_level = connected_signals
                                .first()
                                .and_then(|s| Some(env.level(s)))
                                .unwrap_or(TaintLevel::Clean);

                            if let Some(rule) = get_component_input_leakage_rule(
                                &component_type_str,
                                &port,
                                parent_signal_level,
                            ) {
                                match rule {
                                    ComponentLeakageRule::LeakAll => {
                                        // 泄露全部熵
                                        for signal in &connected_signals {
                                            if let Some((_, entropy, _)) =
                                                env.get_leakage_info(signal)
                                            {
                                                let leaked_bits = entropy;
                                                let op = LeakageOp::ComponentIndirect {
                                                    component_type: component_type_str.clone(),
                                                    component_var: var.to_string(),
                                                    port: port.clone(),
                                                };
                                                env.record_leakage(signal, op, leaked_bits);
                                            } else {
                                                // 没有 tracker，使用默认 254 bits
                                                env.init_leakage_tracker(signal, 254);
                                                let op = LeakageOp::ComponentIndirect {
                                                    component_type: component_type_str.clone(),
                                                    component_var: var.to_string(),
                                                    port: port.clone(),
                                                };
                                                env.record_leakage(signal, op, 254);
                                            }
                                        }
                                    }
                                    ComponentLeakageRule::FixedBits(n) => {
                                        // 固定比特数
                                        for signal in &connected_signals {
                                            let op = LeakageOp::ComponentIndirect {
                                                component_type: component_type_str.clone(),
                                                component_var: var.to_string(),
                                                port: port.clone(),
                                            };
                                            env.record_leakage(signal, op, n);
                                        }
                                    }
                                    ComponentLeakageRule::None => {}
                                }
                            } else {
                                // 分支 B：自定义组件，需要递归分析
                                if let Some(weak_cfg) = env.component_cfg(var) {
                                    if let Some(rc) = weak_cfg.upgrade() {
                                        let child_cfg = rc.borrow();

                                        // 准备子组件的种子
                                        let mut seed = HashMap::new();
                                        for in_name in child_cfg.input_signals() {
                                            let port_level =
                                                env.component_port_level(var, in_name.name());
                                            let level = if !matches!(port_level, TaintLevel::Clean)
                                            {
                                                port_level
                                            } else {
                                                env.component_input_level(var)
                                            };
                                            seed.insert(in_name.clone(), level);
                                        }

                                        // 1. Prepare Cache Key
                                        let mut cache_key_inputs: Vec<(String, TaintLevel)> =
                                            seed.iter().map(|(k, v)| (k.to_string(), *v)).collect();
                                        cache_key_inputs.sort_by(|a, b| a.0.cmp(&b.0));
                                        let cache_key =
                                            (child_cfg.name().to_string(), cache_key_inputs);

                                        // 2. Check Cache
                                        let cached_results = if let Some(res) =
                                            env.component_cache.borrow().get(&cache_key)
                                        {
                                            Some(res.clone())
                                        } else {
                                            None
                                        };

                                        // 3. Run or Use Cache
                                        let results = if let Some(r) = cached_results {
                                            r
                                        } else {
                                            let mut child_env = create_child_env(&env);
                                            run_privacy_taint_on_env(
                                                &child_cfg,
                                                &seed,
                                                &mut child_env,
                                                ctx,
                                            );

                                            let mut new_results = Vec::new();
                                            for child_input in child_cfg.input_signals() {
                                                if let Some((leaked, _, _)) =
                                                    child_env.get_leakage_info(child_input)
                                                {
                                                    if leaked > 0 {
                                                        new_results.push((
                                                            child_input.name().to_string(),
                                                            leaked,
                                                        ));
                                                    }
                                                }
                                            }
                                            env.component_cache
                                                .borrow_mut()
                                                .insert(cache_key, new_results.clone());
                                            new_results
                                        };

                                        // 4. Update Parent (filtering for current port)
                                        for (leaked_port_name, leaked_bits) in results {
                                            if leaked_port_name == port {
                                                for signal in &connected_signals {
                                                    let op = LeakageOp::ComponentIndirect {
                                                        component_type: component_type_str.clone(),
                                                        component_var: var.to_string(),
                                                        port: port.clone(),
                                                    };
                                                    env.record_leakage(signal, op, leaked_bits);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// 为 main component 运行隠私污点分析，支持 public 列表
///
/// 参数：
/// - cfg: main template 的 CFG
/// - public_inputs: 在 main component 中声明为 public 的信号名列表
/// - threshold: 量化泄露报警阈值 (T(x))
pub fn run_privacy_taint_for_main(
    cfg: &Cfg,
    public_inputs: &[String],
    threshold: usize,
    min_severity: LeakSeverity,
) -> PrivacyTaint {
    debug!(
        "running privacy taint analysis for main component with public inputs: {:?}, threshold: {}",
        public_inputs, threshold
    );
    let mut env = PrivacyTaint::with_threshold(threshold).with_min_severity(min_severity);

    // panic!("I AM RUNNING FOR MAIN");

    // 1) 初始化污点源：
    //    - 所有 input 信号默认为 private (Tainted)
    //    - 但在 public_inputs 列表中的信号除外 (Clean)
    for name in cfg.private_input_signals() {
        if public_inputs.contains(&name.to_string()) {
            // 在 public 列表中，标记为 Clean
            trace!("标记公开输入 `{:?}` 为 Clean", name);
            env.set_level(name, TaintLevel::Clean);
        } else {
            // 不在 public 列表中，标记为 Tainted
            trace!("标记私有输入 `{:?}` 为污染", name);
            env.set_level(name, TaintLevel::Tainted);
            env.init_leakage_tracker(name, 254); // 默认 254 比特熵
        }
    }

    // 1.5) 预扫描组件类型与子CFG，并链接到子CFG（CfgManager）
    for bb in cfg.iter() {
        for stmt in bb.iter() {
            if let Statement::Substitution { meta, var, rhe, .. } = stmt {
                if let Some(vtype) = meta.type_knowledge().variable_type() {
                    if matches!(
                        vtype,
                        program_structure::ir::VariableType::Component
                            | program_structure::ir::VariableType::AnonymousComponent
                    ) {
                        if let Expression::Call { name, target_cfg, .. } = rhe {
                            env.set_component_type(var, name);
                            if let Some(weak) = target_cfg {
                                env.set_component_cfg(var, weak);
                            }
                        }
                    }
                }
                // 聚合组件输入：识别 `update(var, access, expr)` 且 access 含 `ComponentAccess`
                if let Expression::Update { var: uvar, access, rhe: inner, .. } = rhe {
                    // 检查是否是组件端口连接
                    for a in access {
                        if let AccessType::ComponentAccess(port) = a {
                            if uvar == var {
                                // 传播组件类型（处理 SSA 变量版本）
                                if let Some(ty) = env.component_type(uvar).map(|s| s.to_string()) {
                                    env.set_component_type(var, &ty);
                                }

                                // 这是组件端口连接（如 component.port <== expr）
                                let level = eval_expr_level(inner, &env);
                                env.add_component_input(var, level);
                                env.add_component_port_level(var, port, level);

                                // 新增：提取并记录连接的信号
                                let connected_signals = extract_signal_names(inner);
                                if !connected_signals.is_empty() {
                                    // debug!("Recording component input connection: {:?}.{} <== {:?}", var, port, connected_signals);
                                    env.record_component_input_connection(
                                        var,
                                        port,
                                        connected_signals,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 2) 迭代传播
    let mut changed = true;
    let mut iter = 0usize;
    while changed && iter < 256 {
        changed = false;
        iter += 1;
        for bb in cfg.iter() {
            for stmt in bb.iter() {
                use Statement::*;
                match stmt {
                    Substitution { var, rhe, .. } => {
                        let rhs_level = eval_expr_level(rhe, &env);
                        // 检测是否是组件输出访问（如 component.out）
                        let is_component_output_access = matches!(rhe, Expression::Access { access, .. } 
                            if access.iter().any(|a| matches!(a, AccessType::ComponentAccess(_))));

                        // 对于组件输出访问，使用直接设置而非 join，以保留精确的污点等级
                        if is_component_output_access {
                            changed = env.set_level_direct(var, rhs_level) || changed;
                        } else {
                            changed = env.set_level(var, rhs_level) || changed;
                        }
                    }
                    Declaration { names, dimensions, .. } => {
                        let dim_level = dimensions
                            .iter()
                            .fold(TaintLevel::Clean, |acc, e| acc.join(eval_expr_level(e, &env)));
                        for name in names {
                            changed = env.set_level(name, dim_level) || changed;
                        }
                    }
                    IfThenElse { cond, .. } => {
                        let c = eval_expr_level(cond, &env);
                        if matches!(c, TaintLevel::Tainted | TaintLevel::PartialLeak) {
                            for sink in bb.variables_written() {
                                changed =
                                    env.set_level(sink.name(), TaintLevel::Tainted) || changed;
                            }
                        }
                    }
                    ConstraintEquality { .. } | Return { .. } | LogCall { .. } | Assert { .. } => {}
                }
            }
        }
    }

    // 3) 回溯子组件泄露到父组件信号
    debug!("Step 3: Back-propagating component leakage to parent signals");
    for bb in cfg.iter() {
        for stmt in bb.iter() {
            if let Statement::Substitution { var, .. } = stmt {
                // 检查是否是组件变量（通过预扫描建立的映射）
                if let Some(component_type_str) = env.component_type(var).map(|s| s.to_string()) {
                    // debug!("Processing component: {:?} of type {}", var, component_type_str);

                    // 获取组件的所有输入端口连接
                    if let Some(port_connections) =
                        env.component_input_connections.get(var).cloned()
                    {
                        for (port, connected_signals) in port_connections.into_iter() {
                            let port: String = port;
                            debug!("  Port: {}, connected signals: {:?}", port, connected_signals);

                            // 分支 A：尝试库组件规则
                            let parent_signal_level = connected_signals
                                .first()
                                .and_then(|s| Some(env.level(s)))
                                .unwrap_or(TaintLevel::Clean);

                            if let Some(rule) = get_component_input_leakage_rule(
                                &component_type_str,
                                &port,
                                parent_signal_level,
                            ) {
                                debug!("  Using library component rule: {:?}", rule);
                                println!(
                                    "[DEBUG] Rule hit for {}.{}: {:?}",
                                    component_type_str, port, rule
                                );

                                match rule {
                                    ComponentLeakageRule::LeakAll => {
                                        // 泄露全部熵
                                        for signal in &connected_signals {
                                            if let Some((_, entropy, _)) =
                                                env.get_leakage_info(signal)
                                            {
                                                let leaked_bits = entropy;
                                                let op = LeakageOp::ComponentIndirect {
                                                    component_type: component_type_str.clone(),
                                                    component_var: var.to_string(),
                                                    port: port.clone(),
                                                };
                                                env.record_leakage(signal, op, leaked_bits);
                                                debug!(
                                                    "    Recorded LeakAll for signal {:?}: {} bits",
                                                    signal, leaked_bits
                                                );
                                            } else {
                                                // 没有 tracker，使用默认 254 bits
                                                env.init_leakage_tracker(signal, 254);
                                                let op = LeakageOp::ComponentIndirect {
                                                    component_type: component_type_str.clone(),
                                                    component_var: var.to_string(),
                                                    port: port.clone(),
                                                };
                                                env.record_leakage(signal, op, 254);
                                                debug!("    Recorded LeakAll for signal {:?}: 254 bits (default)", signal);
                                            }
                                        }
                                    }
                                    ComponentLeakageRule::FixedBits(n) => {
                                        // 固定比特数
                                        for signal in &connected_signals {
                                            let op = LeakageOp::ComponentIndirect {
                                                component_type: component_type_str.clone(),
                                                component_var: var.to_string(),
                                                port: port.clone(),
                                            };
                                            env.record_leakage(signal, op, n);
                                            debug!(
                                                "    Recorded FixedBits for signal {:?}: {} bits",
                                                signal, n
                                            );
                                        }
                                    }
                                    ComponentLeakageRule::None => {
                                        // 无量化泄露
                                        debug!("    No quantified leakage for this component type");
                                    }
                                }
                            } else {
                                // 分支 B：自定义组件，需要递归分析
                                debug!("  Using recursive analysis for custom component");

                                if let Some(weak_cfg) = env.component_cfg(var) {
                                    if let Some(rc) = weak_cfg.upgrade() {
                                        let child_cfg = rc.borrow();

                                        // 准备子组件的种子
                                        let mut seed = HashMap::new();
                                        for in_name in child_cfg.input_signals() {
                                            let port_level =
                                                env.component_port_level(var, in_name.name());
                                            let level = if !matches!(port_level, TaintLevel::Clean)
                                            {
                                                port_level
                                            } else {
                                                env.component_input_level(var)
                                            };
                                            seed.insert(in_name.clone(), level);
                                        }

                                        // 递归分析子组件
                                        let child_env =
                                            run_privacy_taint_with_seed(&child_cfg, &seed, None);

                                        // 提取子组件输入信号的泄露信息
                                        for child_input in child_cfg.input_signals() {
                                            if let Some((leaked, _, _)) =
                                                child_env.get_leakage_info(child_input)
                                            {
                                                if leaked > 0 {
                                                    // 回溯到父组件信号
                                                    for signal in &connected_signals {
                                                        let op = LeakageOp::ComponentIndirect {
                                                            component_type: component_type_str
                                                                .clone(),
                                                            component_var: var.to_string(),
                                                            port: port.clone(),
                                                        };
                                                        env.record_leakage(signal, op, leaked);
                                                        debug!("    Recorded recursive leakage for signal {:?}: {} bits", signal, leaked);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 4) 收集量化泄露信息（Fixpoint 之后运行一次）
    for bb in cfg.iter() {
        for stmt in bb.iter() {
            if let Statement::Substitution { rhe, .. } = stmt {
                track_expr_leakage(rhe, cfg, &mut env, None);
            }
        }
    }

    env
}

/// 隐私污点泄露警告：私有污染的输出信号
pub struct PrivateTaintedOutputWarning {
    signal_name: VariableName,
    taint_level: TaintLevel,
    sources: Vec<String>,
    file_id: Option<FileID>,
    primary_location: FileLocation,
}

impl PrivateTaintedOutputWarning {
    pub fn into_report(self) -> Report {
        let level_desc = match self.taint_level {
            TaintLevel::Tainted => "Tainted",
            TaintLevel::PartialLeak => "PartialLeak",
            TaintLevel::Downgraded => "Downgraded",
            TaintLevel::Clean => "Clean",
        };
        let mut msg = format!("Output signal `{}` is tainted by private inputs (taint level: {}), which may leak privacy.", self.signal_name, level_desc);

        if !self.sources.is_empty() {
            msg.push_str(&format!("\nTainted by: {}", self.sources.join(", ")));
        }

        if matches!(self.taint_level, TaintLevel::PartialLeak) {
            msg.push_str("\nPlease check the associated `QuantifiedLeakage` (CS0021) warnings to identify the specific source of leakage.");
        }

        let mut report = Report::warning(msg, ReportCode::PrivateTaintedOutput);
        if let Some(file_id) = self.file_id {
            report.add_primary(
                self.primary_location,
                file_id,
                format!(
                    "The output signal `{}` is declared here with taint level: {}.",
                    self.signal_name, level_desc
                ),
            );
        }
        report.add_note("Consider using cryptographic primitives like hashing or commitments to protect private information.\nTo ignore this type of result, use `--allow CS0019`.".to_string());
        report
    }
}

/// 隐私污点泄露警告：私有污染的约束
pub struct PrivateTaintedConstraintWarning {
    constraint_location: FileLocation,
    file_id: Option<FileID>,
    tainted_vars: Vec<String>,
}

impl PrivateTaintedConstraintWarning {
    pub fn into_report(self) -> Report {
        let mut report = Report::warning(
            "Constraint contains tainted variables, which may leak private information through the constraint system.".to_string(),
            ReportCode::PrivateTaintedConstraint,
        );
        if let Some(file_id) = self.file_id {
            let vars_list = self.tainted_vars.join(", ");
            report.add_primary(
                self.constraint_location,
                file_id,
                format!("This constraint involves tainted variables: {}", vars_list),
            );
        }
        report.add_note(
            "Consider whether this constraint really needs to expose private information, or redesign the circuit logic.".to_string(),
        );
        report
    }
}

/// 量化泄露警告：带有严重程度分类的部分信息泄露
pub struct QuantifiedLeakageWarning {
    signal_name: VariableName,
    severity: LeakSeverity,
    leaked_bits: usize,
    entropy_bits: usize,
    threshold_bits: usize,
    file_id: Option<FileID>,
    primary_location: FileLocation,
    min_warning_severity: LeakSeverity,
}

impl QuantifiedLeakageWarning {
    pub fn into_report(self) -> Report {
        let severity_desc = match self.severity {
            LeakSeverity::Low => "Low",
            LeakSeverity::Medium => "Medium",
            LeakSeverity::High => "High",
            LeakSeverity::Critical => "Critical",
        };

        let mut report = if self.severity >= self.min_warning_severity {
            Report::warning(
                format!(
                    "Private signal `{}` has quantified information leakage (Severity: {}, L(x)={} bits, H(x)={} bits, T(x)={} bits)",
                    self.signal_name, severity_desc, self.leaked_bits, self.entropy_bits, self.threshold_bits
                ),
                ReportCode::QuantifiedLeakage,
            )
        } else {
            Report::info(
                format!(
                    "Private signal `{}` has quantified information leakage (Severity: {}, L(x)={} bits, H(x)={} bits, T(x)={} bits)",
                    self.signal_name, severity_desc, self.leaked_bits, self.entropy_bits, self.threshold_bits
                ),
                ReportCode::QuantifiedLeakage,
            )
        };

        if let Some(file_id) = self.file_id {
            report.add_primary(
                self.primary_location,
                file_id,
                format!(
                    "Signal `{}` declared here: leaked {} bits out of {} bits entropy (threshold: {} bits)",
                    self.signal_name, self.leaked_bits, self.entropy_bits, self.threshold_bits
                ),
            );
        }

        report.add_note(format!(
            "This signal leaks {} bits through operations like comparisons, bit extraction, or shifts. \
             The threshold for concern is {} bits (12.5% of entropy). Consider using cryptographic \
             primitives to reduce information leakage.",
            self.leaked_bits, self.threshold_bits
        ));

        report
    }
}

/// 隐私污点分析带泄露检测和报告
pub fn find_privacy_taint_leaks(
    cfg: &Cfg,
    ctx: Option<&dyn AnalysisContext>,
    threshold: usize,
    min_severity: LeakSeverity,
) -> ReportCollection {
    debug!("running privacy taint leak detection analysis");

    let mut env = run_privacy_taint_with_ctx(cfg, ctx, threshold, min_severity);
    let mut reports = ReportCollection::new();

    // 在输出赋值和约束中跟踪泄露操作
    for bb in cfg.iter() {
        for stmt in bb.iter() {
            match stmt {
                Statement::Substitution { var, rhe, .. } => {
                    // 如果这是输出信号赋值，跟踪泄露
                    if cfg.output_signals().any(|s| s == var) {
                        track_expr_leakage(rhe, cfg, &mut env, ctx);
                    }
                    // 同时检查 rhe 是否是 Update 表达式（数组赋值）
                    if let Expression::Update { var: update_var, rhe: update_rhe, .. } = rhe {
                        if cfg.output_signals().any(|s| s == update_var) {
                            track_expr_leakage(update_rhe, cfg, &mut env, ctx);
                        }
                    }
                }
                Statement::ConstraintEquality { lhe, rhe, .. } => {
                    // 约束暴露关系，跟踪泄露
                    track_expr_leakage(lhe, cfg, &mut env, ctx);
                    track_expr_leakage(rhe, cfg, &mut env, ctx);
                }
                _ => {}
            }
        }
    }

    // 1. 检测输出信号的污点泄露
    for signal_name in cfg.output_signals() {
        let level = env.level(signal_name);
        // 只报告 Tainted 和 PartialLeak 的输出信号
        if matches!(level, TaintLevel::Tainted | TaintLevel::PartialLeak) {
            if let Some(declaration) = cfg.get_declaration(signal_name) {
                reports.push(
                    PrivateTaintedOutputWarning {
                        signal_name: signal_name.clone(),
                        taint_level: level,
                        sources: Vec::new(),
                        file_id: declaration.file_id(),
                        primary_location: declaration.file_location(),
                    }
                    .into_report(),
                );
            }
        }
    }

    // 2. 检测约束中的污点泄露
    for bb in cfg.iter() {
        for stmt in bb.iter() {
            if let Statement::ConstraintEquality { meta, lhe, rhe } = stmt {
                // 收集约束中使用的所有变量及其污点等级
                let mut tainted_vars = Vec::new();

                // 检查左侧表达式
                collect_tainted_vars(lhe, &env, &mut tainted_vars);
                // 检查右侧表达式
                collect_tainted_vars(rhe, &env, &mut tainted_vars);

                // 如果有完全污染（Tainted）的变量出现在约束中，生成警告
                if !tainted_vars.is_empty() {
                    reports.push(
                        PrivateTaintedConstraintWarning {
                            constraint_location: meta.file_location(),
                            file_id: meta.file_id(),
                            tainted_vars,
                        }
                        .into_report(),
                    );
                }
            }
        }
    }

    // 3. 检查量化的部分泄露（PartialLeak 评估）
    for signal_name in cfg.private_input_signals() {
        if let Some(severity) = env.get_leakage_severity(signal_name) {
            if let Some((leaked_bits, entropy, threshold)) = env.get_leakage_info(signal_name) {
                // 生成量化泄露报告
                if let Some(declaration) = cfg.get_declaration(signal_name) {
                    reports.push(
                        QuantifiedLeakageWarning {
                            signal_name: signal_name.clone(),
                            severity,
                            leaked_bits,
                            entropy_bits: entropy,
                            threshold_bits: threshold,
                            file_id: declaration.file_id(),
                            primary_location: declaration.file_location(),
                            min_warning_severity: env.min_warning_severity(),
                        }
                        .into_report(),
                    );
                }
            }
        }
    }

    debug!("privacy taint analysis generated {} reports", reports.len());
    reports
}

/// 为 main component 运行隐私污点分析带泄露检测和报告
///
/// 使用 public 列表来确定哪些输入信号是公开的
pub fn find_privacy_taint_leaks_for_main(
    cfg: &Cfg,
    public_inputs: &[String],
    threshold: usize,
    min_severity: LeakSeverity,
) -> ReportCollection {
    debug!("running privacy taint leak detection analysis for main component");

    let mut env = run_privacy_taint_for_main(cfg, public_inputs, threshold, min_severity);
    let mut reports = ReportCollection::new();
    let mut output_sources: HashMap<VariableName, Vec<String>> = HashMap::new();

    // 在输出赋值和约束中跟踪泄露操作
    for bb in cfg.iter() {
        for stmt in bb.iter() {
            match stmt {
                Statement::Substitution { var, rhe, .. } => {
                    // 如果这是输出信号赋值，跟踪泄露
                    if cfg.output_signals().any(|s| s == var) {
                        // 【关键修改】传递 CFG 用于循环模式识别
                        track_expr_leakage(rhe, cfg, &mut env, None);
                        // 收集直接污染源
                        let mut vars = Vec::new();
                        collect_tainted_vars(rhe, &env, &mut vars);
                        if !vars.is_empty() {
                            output_sources.entry(var.clone()).or_default().extend(vars);
                        }
                    }
                    // 同时检查 rhe 是否是 Update 表达式（数组赋值）
                    if let Expression::Update { var: update_var, rhe: update_rhe, .. } = rhe {
                        if cfg.output_signals().any(|s| s == update_var) {
                            // 【关键修改】传递 CFG 用于循环模式识别
                            track_expr_leakage(update_rhe, cfg, &mut env, None);
                        }
                    }
                }
                Statement::ConstraintEquality { lhe, rhe, .. } => {
                    // 约束暴露关系，跟踪泄露
                    // 【关键修改】传递 CFG 用于循环模式识别
                    track_expr_leakage(lhe, cfg, &mut env, None);
                    track_expr_leakage(rhe, cfg, &mut env, None);
                }
                _ => {}
            }
        }
    }

    // 1. 检测输出信号的污点泄露
    for signal_name in cfg.output_signals() {
        let level = env.level(signal_name);
        // 只报告 Tainted 和 PartialLeak 的输出信号
        if matches!(level, TaintLevel::Tainted | TaintLevel::PartialLeak) {
            if let Some(declaration) = cfg.get_declaration(signal_name) {
                reports.push(
                    PrivateTaintedOutputWarning {
                        signal_name: signal_name.clone(),
                        taint_level: level,
                        sources: output_sources.remove(signal_name).unwrap_or_default(),
                        file_id: declaration.file_id(),
                        primary_location: declaration.file_location(),
                    }
                    .into_report(),
                );
            }
        }
    }

    // 2. 检测约束中的污点泄露
    for bb in cfg.iter() {
        for stmt in bb.iter() {
            if let Statement::ConstraintEquality { meta, lhe, rhe } = stmt {
                // 收集约束中使用的所有变量及其污点等级
                let mut tainted_vars = Vec::new();

                // 检查左侧表达式
                collect_tainted_vars(lhe, &env, &mut tainted_vars);
                // 检查右侧表达式
                collect_tainted_vars(rhe, &env, &mut tainted_vars);

                // 如果有完全污染（Tainted）的变量出现在约束中，生成警告
                if !tainted_vars.is_empty() {
                    reports.push(
                        PrivateTaintedConstraintWarning {
                            constraint_location: meta.file_location(),
                            file_id: meta.file_id(),
                            tainted_vars,
                        }
                        .into_report(),
                    );
                }
            }
        }
    }

    // 3. 检查量化的部分泄露（PartialLeak 评估）
    for signal_name in cfg.private_input_signals() {
        // 跳过 public 列表中的信号
        if public_inputs.contains(&signal_name.to_string()) {
            continue;
        }

        if let Some(severity) = env.get_leakage_severity(signal_name) {
            if let Some((leaked_bits, entropy, threshold)) = env.get_leakage_info(signal_name) {
                // 生成量化泄露报告
                if let Some(declaration) = cfg.get_declaration(signal_name) {
                    reports.push(
                        QuantifiedLeakageWarning {
                            signal_name: signal_name.clone(),
                            severity,
                            leaked_bits,
                            entropy_bits: entropy,
                            threshold_bits: threshold,
                            file_id: declaration.file_id(),
                            primary_location: declaration.file_location(),
                            min_warning_severity: env.min_warning_severity(),
                        }
                        .into_report(),
                    );
                }
            }
        }
    }

    debug!("privacy taint analysis for main generated {} reports", reports.len());
    reports
}

/// 收集表达式中的污染变量
fn collect_tainted_vars(expr: &Expression, env: &PrivacyTaint, tainted_vars: &mut Vec<String>) {
    use Expression::*;
    match expr {
        Variable { name, .. } => {
            if matches!(env.level(name), TaintLevel::Tainted) {
                tainted_vars.push(name.to_string());
            }
        }
        Access { var, .. } => {
            if matches!(env.level(var), TaintLevel::Tainted) {
                tainted_vars.push(var.to_string());
            }
        }
        InfixOp { lhe, rhe, .. } => {
            collect_tainted_vars(lhe, env, tainted_vars);
            collect_tainted_vars(rhe, env, tainted_vars);
        }
        PrefixOp { rhe, .. } => {
            collect_tainted_vars(rhe, env, tainted_vars);
        }
        SwitchOp { cond, if_true, if_false, .. } => {
            collect_tainted_vars(cond, env, tainted_vars);
            collect_tainted_vars(if_true, env, tainted_vars);
            collect_tainted_vars(if_false, env, tainted_vars);
        }
        InlineArray { values, .. } => {
            for v in values {
                collect_tainted_vars(v, env, tainted_vars);
            }
        }
        Update { var, rhe, .. } => {
            if matches!(env.level(var), TaintLevel::Tainted) {
                tainted_vars.push(var.to_string());
            }
            collect_tainted_vars(rhe, env, tainted_vars);
        }
        Call { args, .. } => {
            for arg in args {
                collect_tainted_vars(arg, env, tainted_vars);
            }
        }
        Phi { args, .. } => {
            for name in args {
                if matches!(env.level(name), TaintLevel::Tainted) {
                    tainted_vars.push(name.to_string());
                }
            }
        }
        Number(..) => {}
    }
}

#[cfg(test)]
mod tests {
    use parser::parse_definition;
    use program_structure::cfg::IntoCfg;
    use program_structure::constants::Curve;
    use program_structure::report::ReportCollection;
    use super::*;

    // ============================================================
    // 第1部分：基础算术运算测试
    // ============================================================

    /// 测试：加法运算 z <== x + y
    /// 规则：x v y → z (Tainted)
    /// 状态：✅ 已实现
    #[test]
    fn test_addition_tainted() {
        let src = r#"
            template T() {
                signal input a;
                signal input b;
                signal output c;
                c <== a + b;
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let c = cfg.output_signals().next().unwrap().clone();
        assert_eq!(env.level(&c), TaintLevel::Tainted);
    }

    /// 测试：减法运算 z <== x - y
    /// 规则：x v y → z (Tainted)
    /// 状态：✅ 已实现
    #[test]
    fn test_subtraction_tainted() {
        let src = r#"
            template T() {
                signal input a;
                signal input b;
                signal output c;
                c <== a - b;
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let c = cfg.output_signals().next().unwrap().clone();
        assert_eq!(env.level(&c), TaintLevel::Tainted);
    }

    /// 测试：乘法运算 z <== x * y
    /// 规则：x v y → z (Tainted)
    /// 状态：✅ 已实现
    #[test]
    fn test_multiplication_tainted() {
        let src = r#"
            template T() {
                signal input a;
                signal input b;
                signal output c;
                c <== a * b;
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let c = cfg.output_signals().next().unwrap().clone();
        assert_eq!(env.level(&c), TaintLevel::Tainted);
    }

    /// 测试：除法运算 z <-- x / y
    /// 规则：x v y → z (Tainted)
    /// 状态：✅ 已实现
    /// 注意：除法的赋值与约束是分离的，但污点传播仍然生效
    #[test]
    fn test_division_tainted() {
        let src = r#"
            template T() {
                signal input a;
                signal input b;
                signal output c;
                c <-- a / b;
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let c = cfg.output_signals().next().unwrap().clone();
        assert_eq!(env.level(&c), TaintLevel::Tainted);
    }

    /// 测试：指数运算 z <== x ** n
    /// 规则：x → z (Tainted)
    /// 状态：✅ 已实现
    #[test]
    fn test_power_tainted() {
        let src = r#"
            template T() {
                signal input a;
                signal output c;
                c <== a ** 3;
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let c = cfg.output_signals().next().unwrap().clone();
        assert_eq!(env.level(&c), TaintLevel::Tainted);
    }

    /// 测试：赋值运算 z <== x
    /// 规则：x → z (Tainted)
    /// 状态：✅ 已实现
    #[test]
    fn test_assignment_tainted() {
        let src = r#"
            template T() {
                signal input a;
                signal output c;
                c <== a;
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let c = cfg.output_signals().next().unwrap().clone();
        assert_eq!(env.level(&c), TaintLevel::Tainted);
    }

    // ============================================================
    // 第2部分：位运算与逻辑运算测试
    // ============================================================

    /// 测试：位提取 z <== x & 1
    /// 规则：x → z (PartialLeak)
    /// 状态：✅ 已实现
    #[test]
    fn test_bit_extract_partial() {
        let src = r#"
            template T() {
                signal input a;
                signal output c;
                c <== a & 1;
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let c = cfg.output_signals().next().unwrap().clone();
        assert_eq!(env.level(&c), TaintLevel::PartialLeak);
    }

    /// 测试：位与运算（一般情况） z <== x & y
    /// 规则：x v y → z (PartialLeak，当至少一个是常量)
    /// 状态：✅ 已实现
    #[test]
    fn test_bitwise_and_partial() {
        let src = r#"
            template T() {
                signal input a;
                signal output c;
                c <== a & 0xFF;
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let c = cfg.output_signals().next().unwrap().clone();
        assert_eq!(env.level(&c), TaintLevel::PartialLeak);
    }

    /// 测试：位或运算 z <== x | y
    /// 规则：x v y → z (Tainted)
    /// 状态：✅ 已实现
    #[test]
    fn test_bitwise_or_tainted() {
        let src = r#"
            template T() {
                signal input a;
                signal input b;
                signal output c;
                c <== a | b;
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let c = cfg.output_signals().next().unwrap().clone();
        assert_eq!(env.level(&c), TaintLevel::Tainted);
    }

    /// 测试：位异或运算 z <== x ^ y
    /// 规则：x v y → z (Tainted)
    /// 状态：✅ 已实现
    #[test]
    fn test_bitwise_xor_tainted() {
        let src = r#"
            template T() {
                signal input a;
                signal input b;
                signal output c;
                c <== a ^ b;
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let c = cfg.output_signals().next().unwrap().clone();
        assert_eq!(env.level(&c), TaintLevel::Tainted);
    }

    /// 测试：左移运算 z <== x << n
    /// 规则：x → z (PartialLeak)
    /// 状态：✅ 已实现
    #[test]
    fn test_shift_left_partial() {
        let src = r#"
            template T() {
                signal input a;
                signal output c;
                c <== a << 3;
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let c = cfg.output_signals().next().unwrap().clone();
        assert_eq!(env.level(&c), TaintLevel::PartialLeak);
    }

    /// 测试：右移运算 z <== x >> n
    /// 规则：x → z (PartialLeak)
    /// 状态：✅ 已实现
    #[test]
    fn test_shift_right_partial() {
        let src = r#"
            template T() {
                signal input a;
                signal output c;
                c <== a >> 5;
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let c = cfg.output_signals().next().unwrap().clone();
        assert_eq!(env.level(&c), TaintLevel::PartialLeak);
    }

    /// 测试：逻辑非 z <== 1 - x (模拟 !x)
    /// 规则：x → z (Tainted)
    /// 状态：✅ 已实现
    #[test]
    fn test_logical_not_tainted() {
        let src = r#"
            template T() {
                signal input a;
                signal output c;
                c <== 1 - a;
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let c = cfg.output_signals().next().unwrap().clone();
        assert_eq!(env.level(&c), TaintLevel::Tainted);
    }

    /// 测试：逻辑与 z <== x * y
    /// 规则：x v y → z (Tainted)
    /// 状态：✅ 已实现（通过乘法）
    #[test]
    fn test_logical_and_tainted() {
        let src = r#"
            template T() {
                signal input a;
                signal input b;
                signal output c;
                c <== a * b;
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let c = cfg.output_signals().next().unwrap().clone();
        assert_eq!(env.level(&c), TaintLevel::Tainted);
    }

    /// 测试：逻辑或 z <== x + y - x*y
    /// 规则：x v y → z (Tainted)
    /// 状态：✅ 已实现（匹配特定算术运算组合）
    #[test]
    fn test_logical_or_tainted() {
        let src = r#"
            template T() {
                signal input a;
                signal input b;
                signal output c;
                c <== a + b - a * b;
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let c = cfg.output_signals().next().unwrap().clone();
        assert_eq!(env.level(&c), TaintLevel::Tainted);
    }

    // ============================================================
    // 第3部分：数组索引与MUX测试
    // ============================================================

    /// 测试：数组索引（私有索引） arr[i]
    /// 规则：i → z (Tainted)
    /// 状态：✅ 已实现
    #[test]
    fn test_array_index_private_index_tainted() {
        let src = r#"
            template T() {
                signal input i;
                signal input arr[8];
                signal output z;
                z <== arr[i];
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let z = cfg.output_signals().next().unwrap().clone();
        assert_eq!(env.level(&z), TaintLevel::Tainted);
    }

    /// 测试：数组索引（私有数组） arr[i]
    /// 规则：arr → z (Tainted)
    /// 状态：✅ 已实现
    #[test]
    fn test_array_index_private_array_tainted() {
        let src = r#"
            template T() {
                signal input arr[8];
                signal input i;
                signal output z;
                z <== arr[i];
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let z = cfg.output_signals().next().unwrap().clone();
        assert_eq!(env.level(&z), TaintLevel::Tainted);
    }

    /// 测试：MUX运算 z <== s * a + (1-s) * b
    /// 规则：a v b v s → z (Tainted)
    /// 状态：✅ 已实现（通过算术运算组合）
    #[test]
    fn test_mux_tainted() {
        let src = r#"
            template T() {
                signal input s;
                signal input a;
                signal input b;
                signal output z;
                z <== s * a + (1 - s) * b;
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let z = cfg.output_signals().next().unwrap().clone();
        assert_eq!(env.level(&z), TaintLevel::Tainted);
    }

    // ============================================================
    // 第4部分：比较运算组件测试
    // ============================================================

    /// 测试：小于比较 (LessThan组件)
    /// 规则：任一输入为污点 → 输出为 PartialLeak
    /// 状态：✅ 已实现
    /// 注：GreaterEq, GreaterThan 等比较组件同理返回 PartialLeak
    #[test]
    fn test_less_than_partial_leak() {
        let src = r#"
            template T() {
                signal input a;
                signal input b;
                signal output z;
                component lt = LessThan(252);
                lt.in[0] <== a;
                lt.in[1] <== b;
                z <== lt.out;
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let z = cfg.output_signals().next().unwrap().clone();
        assert_eq!(env.level(&z), TaintLevel::PartialLeak);
    }

    /// 测试：相等比较 (Equal组件)
    /// 规则：任一输入为污点 → 输出为 Tainted
    /// 状态：✅ 已实现
    /// 注：IsZero, IsEqual 等相等判断组件同理返回 Tainted
    #[test]
    fn test_equal_tainted() {
        let src = r#"
            template T() {
                signal input a;
                signal input b;
                signal output z;
                component eq = Equal();
                eq.in[0] <== a;
                eq.in[1] <== b;
                z <== eq.out;
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let z = cfg.output_signals().next().unwrap().clone();
        assert_eq!(env.level(&z), TaintLevel::Tainted);
    }

    // ============================================================
    // 第5部分：位操作组件测试
    // ============================================================

    /// 测试：Num2Bits组件（数字转比特）
    /// 规则：任一输入为污点 → 输出为 Tainted
    /// 状态：✅ 已实现
    /// 注：Bits2Num、Point2Bits等位操作组件同理返回 Tainted
    #[test]
    fn test_num2bits_component_tainted() {
        let src = r#"
            template T(n) {
                signal input a;
                signal output z;
                component n2b = Num2Bits(n);
                n2b.in <== a;
                z <== n2b.out[0];
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let z = cfg.output_signals().next().unwrap().clone();
        assert_eq!(env.level(&z), TaintLevel::Tainted);
    }

    // ============================================================
    // 第6部分：哈希与密码学组件测试
    // ============================================================

    /// 测试：不可逆函数组件（哈希、签名等）
    /// 规则：任一输入为污点 → 输出为 Downgraded
    /// 状态：✅ 已实现
    /// 注：MiMC7, Pedersen, SHA256, Keccak256, EdDSA, EdDSAPoseidon,
    ///     MerkleTreeInclusionProof, SMTVerifier 等密码学组件同理返回 Downgraded
    #[test]
    fn test_poseidon_downgraded() {
        let src = r#"
            template T() {
                signal input a;
                signal output z;
                component h = Poseidon(1);
                h.in[0] <== a;
                z <== h.out;
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let z = cfg.output_signals().next().unwrap().clone();
        assert_eq!(env.level(&z), TaintLevel::Downgraded);
    }

    // ============================================================
    // 第7部分：逻辑与算术组件测试
    // ============================================================

    /// 测试：通用逻辑与算术组件（以AND为例）
    /// 规则：任一输入为污点 → 输出为 Tainted
    /// 状态：✅ 已实现
    /// 注：OR, NOT, XOR, MUX, MultiMux, Add, Sub, Mul 等常规逻辑和算术组件同理返回 Tainted
    #[test]
    fn test_logic_component_tainted() {
        let src = r#"
            template T() {
                signal input a;
                signal input b;
                signal output z;
                component and_gate = And();
                and_gate.in[0] <== a;
                and_gate.in[1] <== b;
                z <== and_gate.out;
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let z = cfg.output_signals().next().unwrap().clone();
        assert_eq!(env.level(&z), TaintLevel::Tainted);
    }

    // ============================================================
    // 第9部分：组合运算与边界情况测试
    // ============================================================

    /// 测试：位提取后再提取（多次PartialLeak）
    /// 规则：PartialLeak的累积（未来可能需要处理）
    /// 状态：⚠️ 部分实现（当前多次PartialLeak仍为PartialLeak，未累积为Tainted）
    #[test]
    fn test_multiple_bit_extract_partial() {
        let src = r#"
            template T() {
                signal input a;
                signal output bit0;
                signal output bit1;
                bit0 <== a & 1;
                bit1 <== (a >> 1) & 1;
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let mut outputs: Vec<_> = cfg.output_signals().collect();
        outputs.sort_by_key(|v| v.name());
        // 当前实现：每个单独的位提取都是PartialLeak
        assert_eq!(env.level(&outputs[0]), TaintLevel::PartialLeak);
        assert_eq!(env.level(&outputs[1]), TaintLevel::PartialLeak);
    }

    /// 测试：Clean信号的传播
    /// 规则：Clean信号不污染输出
    /// 状态：✅ 已实现
    #[test]
    fn test_clean_signal() {
        // 测试：所有 input 默认为 private，所以结果应该是 Tainted
        let src = r#"
            template T() {
                signal input a;
                signal input b;
                signal output c;
                c <== a + b;
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let c = cfg.output_signals().next().unwrap().clone();
        // 所有 input 都是 private，所以结果应该是 Tainted
        assert_eq!(env.level(&c), TaintLevel::Tainted);
    }

    /// 测试：Downgraded与Tainted的组合
    /// 规则：Tainted优先级更高
    /// 状态：✅ 已实现
    #[test]
    fn test_downgraded_tainted_combination() {
        let src = r#"
            template T() {
                signal input secret;
                signal output hashed;
                signal output combined;
                component h = Poseidon(1);
                h.in[0] <== secret;
                hashed <== h.out;  // Downgraded
                combined <== hashed + secret;  // Downgraded + Tainted = Tainted
            }
        "#;
        let mut reports = ReportCollection::new();
        let cfg = parse_definition(src)
            .unwrap()
            .into_cfg(&Curve::default(), &mut reports)
            .unwrap()
            .into_ssa()
            .unwrap();
        let env = run_privacy_taint(&cfg, 8, LeakSeverity::High);
        let mut outputs: Vec<_> = cfg.output_signals().collect();
        outputs.sort_by_key(|v| v.name());
        // combined应该是Tainted
        assert_eq!(env.level(&outputs[0]), TaintLevel::Tainted);
        // hashed应该是Downgraded
        assert_eq!(env.level(&outputs[1]), TaintLevel::Downgraded);
    }

    /// 测试：条件分支中的污点传播
    /// TODO

    /// =================================
    /// 第10部分：子电路递归分析测试
    /// ==================================

    #[test]
    fn test_subcircuit_pass_through_taint() {
        use crate::analysis_runner::AnalysisRunner;
        use program_structure::constants::Curve;

        let child_src = r#"
            template Child() {
                signal input x;
                signal output y;
                y <== x;
            }
        "#;

        let parent_src = r#"
            template Parent() {
                signal input a;
                signal output z;
                component child = Child();
                child.x <== a;
                z <== child.y;
            }
        "#;

        let mut runner = AnalysisRunner::new(Curve::default()).with_src(&[child_src, parent_src]);
        runner.generate_all_cfgs();
        let cfg_manager = runner.link_all_cfg_references();

        // 获取父电路 CFG 并分析
        if let Some(parent_cfg_ref) = cfg_manager.get_template_cfg_ref("Parent") {
            let parent_cfg = parent_cfg_ref.borrow();
            let env = run_privacy_taint(&parent_cfg, 8, LeakSeverity::High);
            let z = parent_cfg.output_signals().next().unwrap().clone();
            assert_eq!(
                env.level(&z),
                TaintLevel::Tainted,
                "Parent output should inherit child's taint"
            );
        } else {
            panic!("Failed to get Parent CFG");
        }
    }

    #[test]
    fn test_subcircuit_bit_extract_partial() {
        use crate::analysis_runner::AnalysisRunner;
        use program_structure::constants::Curve;

        let extractor_src = r#"
            template BitExtractor() {
                signal input val;
                signal output bit;
                bit <== val & 1;
            }
        "#;

        let parent_src = r#"
            template Parent() {
                signal input secret;
                signal output leaked_bit;
                component extractor = BitExtractor();
                extractor.val <== secret;
                leaked_bit <== extractor.bit;
            }
        "#;

        let mut runner =
            AnalysisRunner::new(Curve::default()).with_src(&[extractor_src, parent_src]);
        runner.generate_all_cfgs();
        let cfg_manager = runner.link_all_cfg_references();

        if let Some(parent_cfg_ref) = cfg_manager.get_template_cfg_ref("Parent") {
            let parent_cfg = parent_cfg_ref.borrow();
            let env = run_privacy_taint(&parent_cfg, 8, LeakSeverity::High);
            let leaked_bit = parent_cfg.output_signals().next().unwrap().clone();

            // 子电路内部的 val & 1 会计算出 PartialLeak
            // 父电路应该能够收到这个精确的污点等级
            assert_eq!(
                env.level(&leaked_bit),
                TaintLevel::PartialLeak,
                "Subcircuit PartialLeak should propagate to parent"
            );
        } else {
            panic!("Failed to get Parent CFG");
        }
    }

    #[test]
    fn test_nested_subcircuits_recursive() {
        use crate::analysis_runner::AnalysisRunner;
        use program_structure::constants::Curve;

        let level2_src = r#"
            template Level2() {
                signal input x;
                signal output y;
                y <== x * x;
            }
        "#;

        let level1_src = r#"
            template Level1() {
                signal input a;
                signal output b;
                component l2 = Level2();
                l2.x <== a;
                b <== l2.y;
            }
        "#;

        let level0_src = r#"
            template Level0() {
                signal input secret;
                signal output result;
                component l1 = Level1();
                l1.a <== secret;
                result <== l1.b;
            }
        "#;

        let mut runner =
            AnalysisRunner::new(Curve::default()).with_src(&[level2_src, level1_src, level0_src]);
        runner.generate_all_cfgs();
        let cfg_manager = runner.link_all_cfg_references();

        if let Some(level0_cfg_ref) = cfg_manager.get_template_cfg_ref("Level0") {
            let level0_cfg = level0_cfg_ref.borrow();
            let env = run_privacy_taint(&level0_cfg, 8, LeakSeverity::High);
            let result = level0_cfg.output_signals().next().unwrap().clone();
            assert_eq!(
                env.level(&result),
                TaintLevel::Tainted,
                "Nested subcircuit should propagate taint"
            );
        } else {
            panic!("Failed to get Level0 CFG");
        }
    }

    #[test]
    fn test_subcircuit_multiple_outputs_mixed_taint() {
        use crate::analysis_runner::AnalysisRunner;
        use program_structure::constants::Curve;

        let multi_src = r#"
            template MultiOutput() {
                signal input x;
                signal output direct;
                signal output extracted_bit;
                direct <== x;
                extracted_bit <== x & 1;
            }
        "#;

        let parent_src = r#"
            template Parent() {
                signal input a;
                signal output out1;
                signal output out2;
                component multi = MultiOutput();
                multi.x <== a;
                out1 <== multi.direct;
                out2 <== multi.extracted_bit;
            }
        "#;

        let mut runner = AnalysisRunner::new(Curve::default()).with_src(&[multi_src, parent_src]);
        runner.generate_all_cfgs();
        let cfg_manager = runner.link_all_cfg_references();

        if let Some(parent_cfg_ref) = cfg_manager.get_template_cfg_ref("Parent") {
            let parent_cfg = parent_cfg_ref.borrow();
            let env = run_privacy_taint(&parent_cfg, 8, LeakSeverity::High);
            let mut outputs: Vec<_> = parent_cfg.output_signals().collect();
            outputs.sort_by_key(|v| v.name());

            // out1 应该完全污染，out2 也是完全污染（因为是单操作数位运算）
            assert_eq!(
                env.level(&outputs[0]),
                TaintLevel::Tainted,
                "Direct output should be tainted"
            );
            assert_eq!(
                env.level(&outputs[1]),
                TaintLevel::Tainted,
                "Bit operation output should be tainted"
            );
        } else {
            panic!("Failed to get Parent CFG");
        }
    }

    // ============================================================
    // 第11部分：PartialLeak 累积
    // ============================================================

    // 示例01：基础泄露（位提取 + 比较），总泄露 < 阈值（不触发量化报告）
    // cargo run -p circomspect -- examples\partial_leak_tests\01_basic_leak.circom

    // 示例02：位移操作 + 位提取组合（累计泄露但低于阈值）
    // cargo run -p circomspect -- examples\partial_leak_tests\02_shift_leak.circom

    // 示例03：高泄露（10次位提取）—应超过阈值（产生量化报告）
    // cargo run -p circomspect -- examples\partial_leak_tests\03_high_leakage.circom

    // 示例04：去重机制（重复位提取不重复计数）
    // cargo run -p circomspect -- examples\partial_leak_tests\04_deduplication.circom

    // ============================================================
    // 第12部分：组件间泄露回溯测试
    // ============================================================

    /// 测试：验证自定义组件泄露回溯（场景 2）
    #[test]
    fn test_custom_component_leakage_backpropagation() {
        use crate::analysis_runner::AnalysisRunner;
        use program_structure::constants::Curve;

        // 自定义子组件（位提取）
        let child_src = r#"
            template CustomBitExtractor(n) {
                signal input in;
                signal output out[n];
                for (var i = 0; i<n; i++) {
                    out[i] <-- (in >> i) & 1;
                }
            }
        "#;

        // 父组件（使用自定义子组件）
        let parent_src = r#"
            template Parent() {
                signal input secret;
                signal output result[8];
                component extractor = CustomBitExtractor(8);
                extractor.in <== secret;
                for (var i = 0; i<8; i++) {
                    result[i] <== extractor.out[i];
                }
            }
        "#;

        let mut runner = AnalysisRunner::new(Curve::default()).with_src(&[child_src, parent_src]);
        runner.generate_all_cfgs();
        let cfg_manager = runner.link_all_cfg_references();

        let parent_cfg_ref = cfg_manager.get_template_cfg_ref("Parent").unwrap();
        let parent_cfg = parent_cfg_ref.borrow();

        // 使用修改后的分析函数
        let reports = find_privacy_taint_leaks_for_main(&parent_cfg, &[], 8, LeakSeverity::High);

        // 验证：父组件的 secret 信号应该有泄露记录
        let cs0021_reports: Vec<_> =
            reports.iter().filter(|r| matches!(r.code(), ReportCode::QuantifiedLeakage)).collect();

        assert!(!cs0021_reports.is_empty(), "父组件输入应该有量化泄露记录（通过自定义子组件回溯）");

        println!("✅ 自定义组件泄露回溯测试通过：找到 {} 个 CS0021 报告", cs0021_reports.len());
    }

    /// 测试：验证库组件规则覆盖
    #[test]
    fn test_component_leakage_rules() {
        // 验证各种库组件的规则
        assert_eq!(
            get_component_input_leakage_rule("Num2Bits", "in", TaintLevel::Tainted),
            Some(ComponentLeakageRule::LeakAll)
        );

        assert_eq!(
            get_component_input_leakage_rule("LessThan", "in", TaintLevel::Tainted),
            Some(ComponentLeakageRule::LeakAll)
        );

        assert_eq!(
            get_component_input_leakage_rule("IsEqual", "in", TaintLevel::Tainted),
            Some(ComponentLeakageRule::FixedBits(1))
        );

        assert_eq!(
            get_component_input_leakage_rule("Poseidon", "in", TaintLevel::Tainted),
            Some(ComponentLeakageRule::None)
        );

        // 自定义组件应返回 None（需要递归分析）
        assert_eq!(
            get_component_input_leakage_rule("MyCustomComponent", "in", TaintLevel::Tainted),
            None
        );

        println!("✅ 库组件规则测试通过");
    }
}
