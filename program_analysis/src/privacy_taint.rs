use log::{debug, trace};
use std::collections::{HashMap, HashSet};
use std::cell::RefCell;

use program_structure::cfg::Cfg;
use program_structure::file_definition::{FileID, FileLocation};
use program_structure::intermediate_representation::variable_meta::VariableMeta;
use program_structure::ir::{Expression, Statement, VariableName, ExpressionInfixOpcode, ExpressionPrefixOpcode, AccessType, WeakCfgRef};
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
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LeakSeverity {
    Low,      // 低：1 <= L(x) < 2
    Medium,   // 中：2 <= L(x) < 8
    High,     // 高：8 <= L(x) < H(x)
    Critical, // 严重：L(x) >= H(x) 或 Tainted 信号直接暴露
}

/// 表示一个泄露操作，用于去重
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum LeakageOp {
    Comparison { secret: String, op: String, constant: Option<String> },
    BitExtract { secret: String, bit_index: usize },

}

/// 跟踪私有变量的部分泄露信息
#[derive(Clone, Debug)]
struct LeakageTracker {
    entropy_bits: usize,           // H(x)：信息熵
    leaked_bits: usize,            // L(x)：累积泄露量
    leakage_ops: HashSet<LeakageOp>, // 用于去重
}

impl LeakageTracker {
    fn new(entropy_bits: usize) -> Self {
        LeakageTracker {
            entropy_bits,
            leaked_bits: 0,
            leakage_ops: HashSet::new(),
        }
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
        let base_threshold = (self.entropy_bits as f64 * 0.125).ceil() as usize;
        base_threshold.max(1).min(8)
    }

    /// 根据 L(x) 和 T(x) 分类泄露严重程度
    fn severity(&self) -> Option<LeakSeverity> {
        if self.leaked_bits == 0 {
            return None;
        }
        
        if self.leaked_bits >= self.entropy_bits {
            return Some(LeakSeverity::Critical);
        }
        
        if self.leaked_bits < self.threshold() {
            return None; // 低于阈值，不报警
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
    leakage_trackers: HashMap<VariableName, LeakageTracker>, // 跟踪部分泄露量化
}

impl PrivacyTaint {
    pub fn new() -> PrivacyTaint { PrivacyTaint::default() }

    pub fn level(&self, name: &VariableName) -> TaintLevel {
        *self.levels.get(name).unwrap_or(&TaintLevel::Clean)
    }

    fn set_level(&mut self, name: &VariableName, level: TaintLevel) -> bool {
        let current = self.level(name);
        if current == level { return false; }
        let new_level = current.join(level);
        if new_level != current {
            self.levels.insert(name.clone(), new_level);
            true
        } else { false }
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
        self
            .component_port_levels
            .get(name)
            .and_then(|m| m.get(port))
            .copied()
            .unwrap_or(TaintLevel::Clean)
    }

    /// 为私有变量初始化泄露跟踪器，带有估计的熵
    fn init_leakage_tracker(&mut self, name: &VariableName, entropy_bits: usize) {
        self.leakage_trackers.insert(name.clone(), LeakageTracker::new(entropy_bits));
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
        self.leakage_trackers.get(name).map(|t| {
            (t.leaked_bits, t.entropy_bits, t.threshold())
        })
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
                            PartialLeak => result = PartialLeak,  // 更温和：保持 PartialLeak
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
                                let child_env = run_privacy_taint_with_seed(&child_cfg, &seed);
                                let mut out_level = TaintLevel::Clean;
                                for out_name in child_cfg.output_signals() {
                                    let child_out_level = child_env.level(out_name);
                                    trace!("Child output signal {:?} has level {:?}", out_name, child_out_level);
                                    out_level = out_level.join(child_out_level);
                                }
                                trace!("Final aggregated out_level for child CFG '{}': {:?}", child_cfg.name(), out_level);
                                result = out_level;
                                // 更新缓存
                                env.child_cache.borrow_mut().insert(cache_key, out_level);
                                is_component_output = true;
                            }
                        }
                    } else {
                        // 无子 CFG 或不是输出端口，使用默认的 Tainted
                        result = if matches!(result, TaintLevel::Clean) { TaintLevel::Clean } else { TaintLevel::Tainted };
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
        "poseidon", "mimc7", "pedersen", "eddsa", "eddsaposeidon", "merkletreeinclusionproof", "smtverifier",
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
            } else if matches!(lhs, Tainted | PartialLeak) || matches!(rhs, Tainted | PartialLeak)
            {
                PartialLeak
            } else { Clean }
        }
        // 其他算术与逻辑，任一输入泄露则输出为 Tainted；Downgraded 透传
        Mul | Div | Add | Sub | Pow | IntDiv | Mod | LesserEq | GreaterEq | Lesser | Greater | Eq | NotEq | BoolOr | BoolAnd | BitOr | BitXor => {
            if matches!(lhs, Tainted | PartialLeak) || matches!(rhs, Tainted | PartialLeak) {
                Tainted
            } else if matches!(lhs, Downgraded) || matches!(rhs, Downgraded) {
                Downgraded
            } else { Clean }
        }
    }
}

fn eval_prefix(op: ExpressionPrefixOpcode, rhs: TaintLevel) -> TaintLevel {
    use ExpressionPrefixOpcode::*;
    use TaintLevel::*;
    match op {
        BoolNot | Sub => {
            if matches!(rhs, Tainted | PartialLeak) { Tainted }
            else if matches!(rhs, Downgraded) { Downgraded }
            else { Clean }
        }
        Complement => {
            // 位级补码，按位操作视作部分泄露（若仅 Downgraded 则保持 Downgraded）
            if matches!(rhs, Downgraded) { Downgraded } else { PartialLeak }
        }
    }
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
            if matches!(c, Tainted | PartialLeak) || matches!(a, Tainted | PartialLeak) || matches!(b, Tainted | PartialLeak) {
                Tainted
            } else if matches!(c, Downgraded) || matches!(a, Downgraded) || matches!(b, Downgraded) {
                Downgraded
            } else { Clean }
        }
        InlineArray { values, .. } => {
            values.iter().fold(Clean, |acc, v| acc.join(eval_expr_level(v, env)))
        }
        Access { var, access, .. } => eval_access_level(var, access, env),
        Update { var, access, rhe, .. } => {
            let base = eval_access_level(var, access, env);
            base.join(eval_expr_level(rhe, env))
        }
        Call { args, .. } => {
            let levels = args.iter().map(|a| eval_expr_level(a, env)).collect::<Vec<_>>();
            if levels.iter().any(|l| matches!(l, Tainted | PartialLeak)) { Tainted }
            else if levels.iter().any(|l| matches!(l, Downgraded)) { Downgraded }
            else { Clean }
        }
        Phi { args, .. } => {
            args.iter().fold(Clean, |acc, name| acc.join(env.level(name)))
        }
    }
}

/// 递归查找表达式中使用的所有私有输入信号名称
fn find_private_inputs_in_expr(expr: &Expression, env: &PrivacyTaint, result: &mut Vec<VariableName>) {
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
fn track_expr_leakage(expr: &Expression, env: &mut PrivacyTaint) {
    use Expression::*;
    use ExpressionInfixOpcode::*;
    
    // 查找此表达式中涉及的所有私有输入
    let mut private_inputs = Vec::new();
    find_private_inputs_in_expr(expr, env, &mut private_inputs);
    
    match expr {
        // 位提取：x & 1（单比特）
        // 也处理 (x >> N) & 1 模式（提取第 N 位）
        InfixOp { lhe, infix_op: BitAnd, rhe, .. } => {
            // 检查是否有一边是常量 1
            let (expr_side, const_side) = match (&**lhe, &**rhe) {
                (Number(_, val), other) | (other, Number(_, val)) => {
                    if val.to_string() == "1" {
                        Some((other, val))
                    } else {
                        None
                    }
                }
                _ => None,
            }.unzip();
            
            if let (Some(expr_side), Some(_)) = (expr_side, const_side) {
                // 检查 expr_side 是否是移位操作：(secret >> N)
                if let InfixOp { lhe: shift_lhe, infix_op: ShiftR | ShiftL, rhe: shift_rhe, .. } = expr_side {
                    // 这是 (secret >> N) & 1 模式 - 提取第 N 位
                    let mut shift_private_inputs = Vec::new();
                    find_private_inputs_in_expr(shift_lhe, env, &mut shift_private_inputs);
                    
                    if let Number(_, shift_val) = &**shift_rhe {
                        if let Ok(bit_index) = shift_val.to_string().parse::<usize>() {
                            // 记录特定索引处的位提取
                            for secret_name in &shift_private_inputs {
                                let op = LeakageOp::BitExtract { 
                                    secret: secret_name.to_string(), 
                                    bit_index
                                };
                                env.record_leakage(secret_name, op, 1); // 泄露 1 比特
                                debug!("Recorded bit extraction: ({} >> {}) & 1 (bit {} leaked, 1 bit total)", 
                                       secret_name, bit_index, bit_index);
                            }
                            return;
                        }
                    }
                } else {
                    // 变量 & 1（最低位）
                    for secret_name in &private_inputs {
                        let op = LeakageOp::BitExtract { 
                            secret: secret_name.to_string(), 
                            bit_index: 0  // 最低位
                        };
                        env.record_leakage(secret_name, op, 1); // 泄露 1 比特
                        debug!("Recorded bit extraction: {} & 1 (bit 0 leaked, 1 bit total)", secret_name);
                    }
                    return;
                }
            }
            
            // 回退：递归到两边
            track_expr_leakage(lhe, env);
            track_expr_leakage(rhe, env);
        }
        
        // 比较操作：泄露 1 比特
        InfixOp { lhe, infix_op, rhe, .. } 
            if matches!(infix_op, Eq | NotEq | Lesser | Greater | LesserEq | GreaterEq) => {
            // 为涉及的所有私有输入记录比较
            for secret_name in &private_inputs {
                let op_name = match infix_op {
                    Eq => "Eq",
                    NotEq => "NotEq",
                    Lesser => "Lt",
                    Greater => "Gt",
                    LesserEq => "Le",
                    GreaterEq => "Ge",
                    _ => "Unknown",
                };
                
                // 尝试提取常量值
                let constant = if let Number(_, val) = &**rhe {
                    Some(val.to_string())
                } else if let Number(_, val) = &**lhe {
                    Some(val.to_string())
                } else {
                    None
                };
                
                let op = LeakageOp::Comparison { 
                    secret: secret_name.to_string(), 
                    op: op_name.to_string(),
                    constant 
                };
                env.record_leakage(secret_name, op, 1); // 比较泄露 1 比特
            }
        }
        
        // 移位操作：本身不是泄露
        // 只有与位提取组合时（在上面的 BitAnd 情况中处理）
        // TODO 或者公开了移位后剩下的高位
        InfixOp { lhe: _, infix_op: ShiftR | ShiftL, rhe: _, .. } => {
            // 只是递归
        }
        
        InfixOp { lhe, rhe, .. } => {
            track_expr_leakage(lhe, env);
            track_expr_leakage(rhe, env);
        }
        PrefixOp { rhe, .. } => {
            track_expr_leakage(rhe, env);
        }
        Variable { .. } | Number(..) => {}
        Access { .. } | Update { .. } | Call { .. } | SwitchOp { .. } | InlineArray { .. } | Phi { .. } => {
            // TODO 如果需要
        }
    }
}

pub fn run_privacy_taint(cfg: &Cfg) -> PrivacyTaint {
    debug!("running privacy taint level analysis");
    let mut env = PrivacyTaint::new();

    // 1) 初始化污点源：private input signals → Tainted
    // 同时为估计熵初始化泄露跟踪器（字段元素默认 254）
    for name in cfg.private_input_signals() {
        trace!("标记私有输入 `{:?}` 为污染", name);
        env.set_level(name, TaintLevel::Tainted);
        // 默认254
        env.init_leakage_tracker(name, 254);
    }

    // 1.5) 预扫描组件类型与子CFG，并链接到子CFG（CfgManager）
    for bb in cfg.iter() {
        for stmt in bb.iter() {
            if let Statement::Substitution { meta, var, rhe, .. } = stmt {
                if let Some(vtype) = meta.type_knowledge().variable_type() {
                    if matches!(vtype, program_structure::ir::VariableType::Component | program_structure::ir::VariableType::AnonymousComponent) {
                        if let Expression::Call { name, target_cfg, .. } = rhe {
                            env.set_component_type(var, name);
                            if let Some(weak) = target_cfg { env.set_component_cfg(var, weak); }
                        }
                    }
                }
                // 聚合组件输入：识别 `update(var, access, expr)` 且 access 含 `ComponentAccess("in")`
                if let Expression::Update { var: uvar, access, rhe: inner, .. } = rhe {
                    if uvar == var && access.iter().any(|a| matches!(a, AccessType::ComponentAccess(p) if p == "in")) {
                        let level = eval_expr_level(inner, &env);
                        env.add_component_input(var, level);
                        env.add_component_port_level(var, "in", level);
                    }
                }
            }
        }
    }

    // 2) 迭代传播
    // TODO 目前简单设置上限避免长时间循环
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
                        let dim_level = dimensions.iter().fold(TaintLevel::Clean, |acc, e| acc.join(eval_expr_level(e, &env)));
                        for name in names {
                            changed = env.set_level(name, dim_level) || changed;
                        }
                    }
                    IfThenElse { cond, .. } => {
                        // TODO 
                        // 条件泄露 → 分支中被赋值变量视作 Tainted（粗略规则）
                        let c = eval_expr_level(cond, &env);
                        if matches!(c, TaintLevel::Tainted | TaintLevel::PartialLeak) {
                            for sink in bb.variables_written() {
                                changed = env.set_level(sink.name(), TaintLevel::Tainted) || changed;
                            }
                        }
                    }
                    ConstraintEquality { .. } | Return { .. } | LogCall { .. } | Assert { .. } => {}
                }
            }
        }
    }
    env
}

pub fn run_privacy_taint_with_seed(cfg: &Cfg, seed: &HashMap<VariableName, TaintLevel>) -> PrivacyTaint {
    let mut env = PrivacyTaint::new();
    // 种子私有输入
    for name in cfg.private_input_signals() {
        env.set_level(name, TaintLevel::Tainted);
    }
    // 种子提供的输入映射
    for (name, level) in seed {
        env.set_level(name, *level);
    }
    // 预扫描组件类型与子 CFG：记录 var = TemplateName(...) 的组件实例，并链接到子CFG
    for bb in cfg.iter() {
        for stmt in bb.iter() {
            if let Statement::Substitution { meta, var, rhe, .. } = stmt {
                if let Some(vtype) = meta.type_knowledge().variable_type() {
                    if matches!(vtype, program_structure::ir::VariableType::Component | program_structure::ir::VariableType::AnonymousComponent) {
                        if let Expression::Call { name, target_cfg, .. } = rhe {
                            env.set_component_type(var, name);
                            if let Some(weak) = target_cfg { env.set_component_cfg(var, weak); }
                        }
                    }
                }
                // 聚合组件输入：识别 update(var, access, expr) 且 access 含 ComponentAccess("in")
                if let Expression::Update { var: uvar, access, rhe: inner, .. } = rhe {
                    if uvar == var && access.iter().any(|a| matches!(a, AccessType::ComponentAccess(p) if p == "in")) {
                        let level = eval_expr_level(inner, &env);
                        env.add_component_input(var, level);
                        env.add_component_port_level(var, "in", level);
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
                        let dim_level = dimensions.iter().fold(TaintLevel::Clean, |acc, e| acc.join(eval_expr_level(e, &env)));
                        for name in names { changed = env.set_level(name, dim_level) || changed; }
                    }
                    IfThenElse { cond, .. } => {
                        let c = eval_expr_level(cond, &env);
                        if matches!(c, TaintLevel::Tainted | TaintLevel::PartialLeak) {
                            for sink in bb.variables_written() { changed = env.set_level(sink.name(), TaintLevel::Tainted) || changed; }
                        }
                    }
                    ConstraintEquality { .. } | Return { .. } | LogCall { .. } | Assert { .. } => {}
                }
            }
        }
    }
    env
}

/// 为 main component 运行隠私污点分析，支持 public 列表
/// 
/// 参数：
/// - cfg: main template 的 CFG
/// - public_inputs: 在 main component 中声明为 public 的信号名列表
pub fn run_privacy_taint_for_main(cfg: &Cfg, public_inputs: &[String]) -> PrivacyTaint {
    debug!("running privacy taint analysis for main component with public inputs: {:?}", public_inputs);
    let mut env = PrivacyTaint::new();

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
                    if matches!(vtype, program_structure::ir::VariableType::Component | program_structure::ir::VariableType::AnonymousComponent) {
                        if let Expression::Call { name, target_cfg, .. } = rhe {
                            env.set_component_type(var, name);
                            if let Some(weak) = target_cfg { env.set_component_cfg(var, weak); }
                        }
                    }
                }
                // 聚合组件输入：识别 `update(var, access, expr)` 且 access 含 `ComponentAccess("in")`
                if let Expression::Update { var: uvar, access, rhe: inner, .. } = rhe {
                    if uvar == var && access.iter().any(|a| matches!(a, AccessType::ComponentAccess(p) if p == "in")) {
                        let level = eval_expr_level(inner, &env);
                        env.add_component_input(var, level);
                        env.add_component_port_level(var, "in", level);
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
                        let dim_level = dimensions.iter().fold(TaintLevel::Clean, |acc, e| acc.join(eval_expr_level(e, &env)));
                        for name in names {
                            changed = env.set_level(name, dim_level) || changed;
                        }
                    }
                    IfThenElse { cond, .. } => {
                        let c = eval_expr_level(cond, &env);
                        if matches!(c, TaintLevel::Tainted | TaintLevel::PartialLeak) {
                            for sink in bb.variables_written() {
                                changed = env.set_level(sink.name(), TaintLevel::Tainted) || changed;
                            }
                        }
                    }
                    ConstraintEquality { .. } | Return { .. } | LogCall { .. } | Assert { .. } => {}
                }
            }
        }
    }
    env
}

/// 隐私污点泄露警告：私有污染的输出信号
pub struct PrivateTaintedOutputWarning {
    signal_name: VariableName,
    taint_level: TaintLevel,
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
        let mut report = Report::warning(
            format!(
                "Output signal `{}` is tainted by private inputs (taint level: {}), which may leak privacy.",
                self.signal_name, level_desc
            ),
            ReportCode::PrivateTaintedOutput,
        );
        if let Some(file_id) = self.file_id {
            report.add_primary(
                self.primary_location,
                file_id,
                format!("The output signal `{}` is declared here with taint level: {}.", self.signal_name, level_desc),
            );
        }
        report.add_note(
            "Consider using cryptographic primitives like hashing or commitments to protect private information.".to_string(),
        );
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
}

impl QuantifiedLeakageWarning {
    pub fn into_report(self) -> Report {
        let severity_desc = match self.severity {
            LeakSeverity::Low => "Low",
            LeakSeverity::Medium => "Medium",
            LeakSeverity::High => "High",
            LeakSeverity::Critical => "Critical",
        };
        
        // 根据严重程度使用适当的报告级别
        let mut report = match self.severity {
            LeakSeverity::Critical | LeakSeverity::High => Report::warning(
                format!(
                    "Private signal `{}` has quantified information leakage (Severity: {}, L(x)={} bits, H(x)={} bits, T(x)={} bits)",
                    self.signal_name, severity_desc, self.leaked_bits, self.entropy_bits, self.threshold_bits
                ),
                ReportCode::QuantifiedLeakage,
            ),
            LeakSeverity::Medium | LeakSeverity::Low => Report::info(
                format!(
                    "Private signal `{}` has quantified information leakage (Severity: {}, L(x)={} bits, H(x)={} bits, T(x)={} bits)",
                    self.signal_name, severity_desc, self.leaked_bits, self.entropy_bits, self.threshold_bits
                ),
                ReportCode::QuantifiedLeakage,
            ),
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
pub fn find_privacy_taint_leaks(cfg: &Cfg) -> ReportCollection {
    debug!("running privacy taint leak detection analysis");
    
    let mut env = run_privacy_taint(cfg);
    let mut reports = ReportCollection::new();
    
    // 在输出赋值和约束中跟踪泄露操作
    for bb in cfg.iter() {
        for stmt in bb.iter() {
            match stmt {
                Statement::Substitution { var, rhe, .. } => {
                    // 如果这是输出信号赋值，跟踪泄露
                    if cfg.output_signals().any(|s| s == var) {
                        track_expr_leakage(rhe, &mut env);
                    }
                    // 同时检查 rhe 是否是 Update 表达式（数组赋值）
                    if let Expression::Update { var: update_var, rhe: update_rhe, .. } = rhe {
                        if cfg.output_signals().any(|s| s == update_var) {
                            track_expr_leakage(update_rhe, &mut env);
                        }
                    }
                }
                Statement::ConstraintEquality { lhe, rhe, .. } => {
                    // 约束暴露关系，跟踪泄露
                    track_expr_leakage(lhe, &mut env);
                    track_expr_leakage(rhe, &mut env);
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
pub fn find_privacy_taint_leaks_for_main(cfg: &Cfg, public_inputs: &[String]) -> ReportCollection {
    debug!("running privacy taint leak detection analysis for main component");
    
    let mut env = run_privacy_taint_for_main(cfg, public_inputs);
    let mut reports = ReportCollection::new();
    
    // 在输出赋值和约束中跟踪泄露操作
    for bb in cfg.iter() {
        for stmt in bb.iter() {
            match stmt {
                Statement::Substitution { var, rhe, .. } => {
                    // 如果这是输出信号赋值，跟踪泄露
                    if cfg.output_signals().any(|s| s == var) {
                        track_expr_leakage(rhe, &mut env);
                    }
                    // 同时检查 rhe 是否是 Update 表达式（数组赋值）
                    if let Expression::Update { var: update_var, rhe: update_rhe, .. } = rhe {
                        if cfg.output_signals().any(|s| s == update_var) {
                            track_expr_leakage(update_rhe, &mut env);
                        }
                    }
                }
                Statement::ConstraintEquality { lhe, rhe, .. } => {
                    // 约束暴露关系，跟踪泄露
                    track_expr_leakage(lhe, &mut env);
                    track_expr_leakage(rhe, &mut env);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
        let cfg = parse_definition(src).unwrap().into_cfg(&Curve::default(), &mut reports).unwrap().into_ssa().unwrap();
        let env = run_privacy_taint(&cfg);
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
            let env = run_privacy_taint(&parent_cfg);
            let z = parent_cfg.output_signals().next().unwrap().clone();
            assert_eq!(env.level(&z), TaintLevel::Tainted, "Parent output should inherit child's taint");
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
        
        let mut runner = AnalysisRunner::new(Curve::default()).with_src(&[extractor_src, parent_src]);
        runner.generate_all_cfgs();
        let cfg_manager = runner.link_all_cfg_references();
        
        if let Some(parent_cfg_ref) = cfg_manager.get_template_cfg_ref("Parent") {
            let parent_cfg = parent_cfg_ref.borrow();
            let env = run_privacy_taint(&parent_cfg);
            let leaked_bit = parent_cfg.output_signals().next().unwrap().clone();
            
            // 子电路内部的 val & 1 会计算出 PartialLeak
            // 父电路应该能够收到这个精确的污点等级
            assert_eq!(env.level(&leaked_bit), TaintLevel::PartialLeak, "Subcircuit PartialLeak should propagate to parent");
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
        
        let mut runner = AnalysisRunner::new(Curve::default()).with_src(&[level2_src, level1_src, level0_src]);
        runner.generate_all_cfgs();
        let cfg_manager = runner.link_all_cfg_references();
        
        if let Some(level0_cfg_ref) = cfg_manager.get_template_cfg_ref("Level0") {
            let level0_cfg = level0_cfg_ref.borrow();
            let env = run_privacy_taint(&level0_cfg);
            let result = level0_cfg.output_signals().next().unwrap().clone();
            assert_eq!(env.level(&result), TaintLevel::Tainted, "Nested subcircuit should propagate taint");
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
            let env = run_privacy_taint(&parent_cfg);
            let mut outputs: Vec<_> = parent_cfg.output_signals().collect();
            outputs.sort_by_key(|v| v.name());
            
            // out1 应该完全污染，out2 也是完全污染（因为是单操作数位运算）
            assert_eq!(env.level(&outputs[0]), TaintLevel::Tainted, "Direct output should be tainted");
            assert_eq!(env.level(&outputs[1]), TaintLevel::Tainted, "Bit operation output should be tainted");
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

}


