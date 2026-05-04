use std::collections::{HashMap, HashSet, VecDeque};
use program_structure::ir::VariableName;
use program_structure::file_definition::{FileLocation, FileID};
use program_structure::report::{Report, ReportCollection};
use program_structure::report_code::ReportCode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CcigVariant {
    Full,
    NoUnroll,
    NoUnrollConservative,
    NoUnrollAggressive,
    SinglePass,
    VanguardLite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CcigRunConfig {
    pub variant: CcigVariant,
}

impl Default for CcigRunConfig {
    fn default() -> Self {
        Self { variant: CcigVariant::Full }
    }
}

/// 泄露强类型描述
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Intensity {
    OneWay,   // 单向传播，无法反向推导
    Partial,  // 位截断/比较，限制了域大小
    Full,     // 无损代数映射，可完全推导
}

/// 攻击者知识状态界限
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KnowledgeState {
    Unknown, // \bot
    PK,      // Partly Known
    FK,      // Fully Known
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SignalKind {
    Input,
    Output,
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SignalVis {
    Pub,
    Priv,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum OpType {
    AddSub,      // 混淆与线性映射
    Mul,         // 混淆与代数混合（非线性）
    BitExtract,  // 降级为 Partial
    Hash,        // 单向阻断，降级为 OneWay
    Select,      // 多输入依赖
    Compare,     // 比较类，输出布尔值，降级为 Partial
    LogicGate,   // 逻辑门，输出布尔值，降级为 Partial
    BlackBoxConservative,
    BlackBoxAggressive,
    Other,       // 保守处理
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NodeType {
    // 信号节点 V_S
    Signal {
        name: VariableName,             // 规范化后的作用域变量名（用于图内唯一定位与索引）。
        original_name: String,          // AST 原生声明名（如 `a`，而非 `a_0_ANY`），用于日志与用户可读报告。
        kind: SignalKind,               // 信号类别：输入 / 输出 / 中间。
        vis: SignalVis,                 // 可见性：公开 / 私有。
        inst: String,                   // 实例化上下文前缀，用于区分组件展开后的同名信号。
        location: Option<FileLocation>, // 语法节点文件位置，用于最终告警定位。
        file_id: Option<FileID>,        // 源文件 ID，与 `location` 共同定位源码位置。
    },
    // 运算节点 V_O
    Op {
        op_type: OpType,                // 运算语义类别，决定阶段传播时的强度传递规则。
    },
    /// 约束节点。
    ///
    /// 主要用于表示 `===` 等值关系，通过 `ConEdge` 把相关信号连通，
    /// 使阶段二可沿等式约束执行双向知识传播。
    Constraint,
}

#[derive(Clone, Debug)]
pub struct Node {
    pub id: usize,
    pub node_type: NodeType,
}

impl Node {
    pub fn new(id: usize, node_type: NodeType) -> Self {
        Self { id, node_type }
    }
}

/// 信息传递流边定义
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EdgeType {
    /// 计算依赖流边 -> (例如 operand -> compute -> target)，带有索引idx以防不可交换代数(暂定默认0)
    CompEdge(usize), 
    /// 无向等于约束连通 -> (例如 s1 <-> === <-> s2) 
    ConEdge,
}

/// 两阶段泄露推断所需的运行时状态
#[derive(Clone, Debug)]
pub struct SignalState {
    /// Phase I: \mathcal{I}(s), 保存所有传导过来的 Private 源信号 ID 及其强度
    pub info_set: HashSet<(usize, Intensity)>, 
    /// Phase II: \mathcal{K}(s)
    pub knowledge: KnowledgeState,
    /// 标志该信号是否通过关系解盲（Relational De-blinding）被推导为泄漏
    pub is_relational_leak: bool,
    pub is_cascade_leak: bool,
    pub cascade_cause: Option<usize>,
}

#[derive(Clone, Debug, Default)]
struct ComponentPortHints {
    input_bases: HashSet<String>,
    output_bases: HashSet<String>,
}

impl SignalState {
    pub fn new() -> Self {
        Self {
            info_set: HashSet::new(),
            knowledge: KnowledgeState::Unknown,
            is_relational_leak: false,
            is_cascade_leak: false,
            cascade_cause: None,
        }
    }
}

/// CCIG & 二阶段预测引擎整体环境
pub struct CcigAnalyzer {
    pub nodes: Vec<Node>,
    /// 构建 CCIG 中存储的信号状态和推理数据
    pub states: HashMap<usize, SignalState>, 

    /// 边映射：node_id -> Vec<(target_id, EdgeType)>
    pub forward_edges: HashMap<usize, Vec<(usize, EdgeType)>>,
    pub backward_edges: HashMap<usize, Vec<(usize, EdgeType)>>,
    
    // 变量名 -> 节点ID
    pub var_to_id: HashMap<VariableName, usize>,
    
    // 用于储存已显式的私有源索引，便于 Phase1 和 Phase2 的对账汇总
    pub private_inputs: HashSet<usize>, 
    
    // 用于存储公共源的索引
    pub public_outputs: HashSet<usize>,
    pub public_inputs: HashSet<usize>,
    pub abstracted_ops: HashMap<String, usize>,
    component_port_hints: HashMap<String, ComponentPortHints>,
    pub variant: CcigVariant,
}

impl CcigAnalyzer {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            states: HashMap::new(),
            forward_edges: HashMap::new(),
            backward_edges: HashMap::new(),
            var_to_id: HashMap::new(),
            private_inputs: HashSet::new(),
            public_inputs: HashSet::new(),
            public_outputs: HashSet::new(),
            abstracted_ops: HashMap::new(),
            component_port_hints: HashMap::new(),
            variant: CcigVariant::Full,
        }
    }

    pub fn add_node(&mut self, node_type: NodeType) -> usize {
        let id = self.nodes.len();
        let node = Node::new(id, node_type.clone());
        self.nodes.push(node);
        self.states.insert(id, SignalState::new());
        
        if let NodeType::Signal { name, kind, vis, inst, .. } = &node_type {
            self.var_to_id.insert(name.clone(), id);
            if inst.is_empty() {
                if kind == &SignalKind::Input && vis == &SignalVis::Priv {
                    self.private_inputs.insert(id);
                } else if vis == &SignalVis::Pub {
                    // 理论上如果是根区块则需要追踪。目前将所有公共 I/O 作为初始工作列表中的种子进行追踪
                    if kind == &SignalKind::Input {
                        self.public_inputs.insert(id);
                    } else if kind == &SignalKind::Output {
                        self.public_outputs.insert(id);
                    }
                }
            }
        }
        id
    }

    pub fn add_comp_edge(&mut self, from: usize, to: usize, idx: usize) {
        self.forward_edges.entry(from).or_default().push((to, EdgeType::CompEdge(idx)));
        self.backward_edges.entry(to).or_default().push((from, EdgeType::CompEdge(idx)));
    }

    pub fn add_con_edge(&mut self, n1: usize, n2: usize) {
        self.forward_edges.entry(n1).or_default().push((n2, EdgeType::ConEdge));
        self.backward_edges.entry(n2).or_default().push((n1, EdgeType::ConEdge));
        
        self.forward_edges.entry(n2).or_default().push((n1, EdgeType::ConEdge));
        self.backward_edges.entry(n1).or_default().push((n2, EdgeType::ConEdge));
    }

    fn get_scoped_var_name(name: &VariableName, prefix: &str) -> VariableName {
        if prefix.is_empty() {
            name.clone()
        } else {
            VariableName::from_string(format!("{}_{}", prefix, name.name()))
        }
    }

    pub fn get_or_create_var_node(&mut self, name: &VariableName, original_name: &str, kind: SignalKind, vis: SignalVis, inst: &str, location: Option<FileLocation>, file_id: Option<FileID>) -> usize {
        if let Some(&id) = self.var_to_id.get(name) {
            id
        } else {
            let id = self.add_node(NodeType::Signal {
                name: name.clone(),
                original_name: original_name.to_string(),
                kind: kind.clone(),
                vis: vis.clone(),
                inst: inst.to_string(),
                location,
                file_id,
            });
            
            // 重新捕获动态发现的输入/输出属性（例如用于像 secret_arr_0 这样被展平的数组）
            if inst.is_empty() {
                if kind == SignalKind::Input && vis == SignalVis::Priv {
                    self.private_inputs.insert(id);
                } else if vis == SignalVis::Pub {
                    if kind == SignalKind::Input {
                        self.public_inputs.insert(id);
                    } else if kind == SignalKind::Output {
                        self.public_outputs.insert(id);
                    }
                }
            }
            id
        }
    }

    fn known_call_op_type(name: &str) -> Option<OpType> {
        let target_name = name.to_lowercase();
        let hash_ops = ["poseidon", "mimc7", "pedersen", "eddsa", "mimcsponge", "hasher", "keccak", "hashbytes"];
        let compare_ops = ["lessthan", "greaterthan", "lesseqthan", "greatereqthan", "iszero", "isequal"];
        let logic_ops = ["and", "or", "xor", "not", "nand", "nor"];

        if hash_ops.iter().any(|&h| target_name.contains(h)) {
            Some(OpType::Hash)
        } else if compare_ops.iter().any(|&c| target_name.contains(c)) {
            Some(OpType::Compare)
        } else if logic_ops.iter().any(|&l| target_name == l || target_name == format!("{}gate", l)) {
            Some(OpType::LogicGate)
        } else {
            None
        }
    }

    fn is_hash_like_text(text: &str) -> bool {
        let lower = text.to_lowercase();
        lower.contains("hash")
            || lower.contains("keccak")
            || lower.contains("mimc")
            || lower.contains("poseidon")
            || lower.contains("sha256")
            || lower.contains("pedersen")
            || lower.contains("blake")
            || lower.contains("commit")
    }

    fn is_hash_like_signal(inst: &str, original_name: &str) -> bool {
        Self::is_hash_like_text(inst) || Self::is_hash_like_text(original_name)
    }

    fn no_unroll_blackbox_op_type(&self) -> OpType {
        match self.variant {
            CcigVariant::NoUnrollConservative | CcigVariant::NoUnroll => OpType::BlackBoxConservative,
            CcigVariant::NoUnrollAggressive => OpType::BlackBoxAggressive,
            _ => OpType::BlackBoxAggressive,
        }
    }

    pub fn build_from_cfg(&mut self, cfg: &program_structure::cfg::Cfg, prefix: &str) {
        use program_structure::ir::{Statement, Expression, VariableType, AccessType, SignalType};

        for bb in cfg.iter() {
            for stmt in bb.iter() {
                match stmt {
                    Statement::Declaration { names, var_type, .. } => {
                        let (kind, vis) = match var_type {
                            VariableType::Signal(SignalType::Input, _, true) => (SignalKind::Input, SignalVis::Priv),
                            VariableType::Signal(SignalType::Input, _, false) => (SignalKind::Input, SignalVis::Pub), 
                            VariableType::Signal(SignalType::Output, _, _) => (SignalKind::Output, SignalVis::Pub),
                            _ => (SignalKind::Internal, SignalVis::Pub),
                        };
                        
                        for name in names {
                            let scoped_name = Self::get_scoped_var_name(name, prefix);
                            self.get_or_create_var_node(&scoped_name, name.name(), kind.clone(), vis.clone(), prefix, Some(stmt.meta().file_location().clone()), stmt.meta().file_id());
                        }
                    }
                    Statement::Substitution { var, rhe, .. } => {
                        let (inner_rhe, access_path) = if let Expression::Update { access, rhe: up_rhe, .. } = rhe {
                            (up_rhe.as_ref(), access.as_slice())
                        } else {
                            (rhe, [].as_slice())
                        };

                        let mut full_lhs_name = Self::get_scoped_var_name(var, prefix).name().clone();
                        for acc in access_path {
                            match acc {
                                AccessType::ArrayAccess(box_expr) => {
                                    if let Expression::Number(_, num) = box_expr.as_ref() { full_lhs_name.push_str(&format!("_{}", num)); } 
                                    else { full_lhs_name.push_str("_ANY"); }
                                }
                                AccessType::ComponentAccess(sig) => full_lhs_name.push_str(&format!("_{}", sig)),
                            }
                        }
                        
                        let scoped_lhs_name = VariableName::from_string(full_lhs_name.clone());

                        // 从父级声明中推断可见性和类型（例如从 secret_arr_0 推断 secret_arr）
                        let mut lhs_kind = SignalKind::Internal;
                        let mut lhs_vis = SignalVis::Pub;
                        let mut lhs_loc = None;
                        let mut lhs_file = None;
                        if let Some(decl) = cfg.declarations().get_declaration(var) {
                            if let VariableType::Signal(sig_type, _, is_priv) = decl.variable_type() {
                                lhs_kind = match sig_type {
                                    SignalType::Input => SignalKind::Input,
                                    SignalType::Output => SignalKind::Output,
                                    _ => SignalKind::Internal,
                                };
                                lhs_vis = if *is_priv { SignalVis::Priv } else { SignalVis::Pub };
                                lhs_loc = Some(decl.file_location());
                                lhs_file = decl.file_id();
                                
                                // 因为这在主声明循环中没有被捕获，所以在这里实例化它
                                self.get_or_create_var_node(&scoped_lhs_name, var.name(), lhs_kind.clone(), lhs_vis.clone(), prefix, lhs_loc.clone(), lhs_file);
                            }
                        }

                        if let Expression::Call { name, target_cfg, .. } = inner_rhe {
                            if let Some(op_kind) = Self::known_call_op_type(name) {
                                let abstract_op = self.add_node(NodeType::Op { op_type: op_kind });
                                self.abstracted_ops.insert(scoped_lhs_name.name().clone(), abstract_op);
                            } else {
                                let should_unroll = matches!(self.variant, CcigVariant::Full | CcigVariant::SinglePass);
                                if should_unroll {
                                    if let Some(weak_cfg) = target_cfg.as_ref() {
                                        if let Some(target_rc) = weak_cfg.upgrade() {
                                            let target_cfg = target_rc.borrow();
                                            self.build_from_cfg(&target_cfg, &full_lhs_name);

                                            if matches!(target_cfg.definition_type(), program_structure::cfg::DefinitionType::Function) {
                                                let lhs_id = self.get_or_create_var_node(&scoped_lhs_name, var.name(), lhs_kind.clone(), lhs_vis.clone(), prefix, lhs_loc.clone(), lhs_file);
                                                for block in target_cfg.iter() {
                                                    for stmt in block.iter() {
                                                        if let program_structure::ir::Statement::Return { value, .. } = stmt {
                                                            let return_id = self.process_expression(value, &target_cfg, &full_lhs_name);
                                                            self.add_comp_edge(return_id, lhs_id, 0);
                                                            let con_id = self.add_node(NodeType::Constraint);
                                                            self.add_con_edge(lhs_id, con_id);
                                                            self.add_con_edge(return_id, con_id);
                                                        }
                                                    }
                                                }
                                                self.connect_substitution_summary_edge(
                                                    &scoped_lhs_name,
                                                    var.name(),
                                                    lhs_kind.clone(),
                                                    lhs_vis.clone(),
                                                    prefix,
                                                    lhs_loc.clone(),
                                                    lhs_file,
                                                    inner_rhe,
                                                    cfg,
                                                );
                                            }
                                        } else {
                                            self.connect_substitution_summary_edge(
                                                &scoped_lhs_name,
                                                var.name(),
                                                lhs_kind.clone(),
                                                lhs_vis.clone(),
                                                prefix,
                                                lhs_loc.clone(),
                                                lhs_file,
                                                inner_rhe,
                                                cfg,
                                            );
                                        }
                                    } else {
                                        self.connect_substitution_summary_edge(
                                            &scoped_lhs_name,
                                            var.name(),
                                            lhs_kind.clone(),
                                            lhs_vis.clone(),
                                            prefix,
                                            lhs_loc.clone(),
                                            lhs_file,
                                            inner_rhe,
                                            cfg,
                                        );
                                    }
                                } else {
                                    let blackbox_op_type = self.no_unroll_blackbox_op_type();
                                    let mut register_component_ports = false;
                                    let mut component_port_hints = None;
                                    if let Expression::Call { target_cfg, .. } = inner_rhe {
                                        if let Some(weak_cfg) = target_cfg.as_ref() {
                                            if let Some(target_rc) = weak_cfg.upgrade() {
                                                let target_cfg = target_rc.borrow();
                                                register_component_ports = matches!(
                                                    target_cfg.definition_type(),
                                                    program_structure::cfg::DefinitionType::Template
                                                );
                                                if register_component_ports {
                                                    component_port_hints = Some(Self::extract_component_port_hints(&target_cfg));
                                                }
                                            }
                                        }
                                    }
                                    self.connect_blackbox_summary_edge(
                                        &scoped_lhs_name,
                                        var.name(),
                                        lhs_kind,
                                        lhs_vis,
                                        prefix,
                                        lhs_loc,
                                        lhs_file,
                                        inner_rhe,
                                        cfg,
                                        blackbox_op_type,
                                        register_component_ports,
                                        component_port_hints,
                                    );
                                }
                            }
                        } else {
                            // 常规替换（如 <==, === 或 = 赋值操作）
                            let lhs_id = self.get_or_create_var_node(&scoped_lhs_name, var.name(), lhs_kind, lhs_vis, prefix, lhs_loc, lhs_file);
                            let rhs_id = self.process_expression(inner_rhe, cfg, prefix);
                            
                            self.add_comp_edge(rhs_id, lhs_id, 0); 
                            let con_id = self.add_node(NodeType::Constraint);
                            self.add_con_edge(lhs_id, con_id);
                            self.add_con_edge(rhs_id, con_id);
                        }
                    }
                    Statement::ConstraintEquality { lhe, rhe, .. } => {
                        let lhs_id = self.process_expression(lhe, cfg, prefix);
                        let rhs_id = self.process_expression(rhe, cfg, prefix);
                        let constraint_id = self.add_node(NodeType::Constraint);
                        self.add_con_edge(lhs_id, constraint_id);
                        self.add_con_edge(constraint_id, rhs_id);
                    }
                    _ => {}
                }
            }
        }
        
        // At the end of parsing for a scope, wire up abstracted ops
        let ops = self.abstracted_ops.clone();
        for (comp_name, op_id) in ops {
            let mut inputs_to_wire = Vec::new();
            let mut outputs_to_wire = Vec::new();
            let hints = self.component_port_hints.get(&comp_name).cloned().unwrap_or_default();
            let comp_prefix = format!("{}_", comp_name);
            for (var_name, &sig_id) in &self.var_to_id {
                let name_str = var_name.name();
                if !name_str.starts_with(&comp_prefix) {
                    continue;
                }

                let mut is_output = hints.output_bases.iter().any(|base| {
                    let p = format!("{}_{}", comp_name, base);
                    name_str == p.as_str() || name_str.starts_with(&(p + "_"))
                });
                let mut is_input = hints.input_bases.iter().any(|base| {
                    let p = format!("{}_{}", comp_name, base);
                    name_str == p.as_str() || name_str.starts_with(&(p + "_"))
                });

                if !is_output && !is_input && name_str.starts_with(&format!("{}_out", comp_name)) {
                    is_output = true;
                }

                if !is_output && !is_input {
                    let outgoing_to_external = self.forward_edges.get(&sig_id).cloned().unwrap_or_default().iter().any(|(to_id, edge_type)| {
                        if !matches!(edge_type, EdgeType::CompEdge(_)) {
                            return false;
                        }
                        if let NodeType::Signal { name, .. } = &self.nodes[*to_id].node_type {
                            !name.name().starts_with(&comp_prefix)
                        } else {
                            false
                        }
                    });
                    let incoming_from_external = self.backward_edges.get(&sig_id).cloned().unwrap_or_default().iter().any(|(from_id, edge_type)| {
                        if !matches!(edge_type, EdgeType::CompEdge(_)) {
                            return false;
                        }
                        if let NodeType::Signal { name, .. } = &self.nodes[*from_id].node_type {
                            !name.name().starts_with(&comp_prefix)
                        } else {
                            false
                        }
                    });

                    if outgoing_to_external && !incoming_from_external {
                        is_output = true;
                    } else if incoming_from_external && !outgoing_to_external {
                        is_input = true;
                    }
                }

                if is_output {
                    outputs_to_wire.push((sig_id, name_str.clone()));
                } else if is_input {
                    inputs_to_wire.push(sig_id);
                } else {
                    inputs_to_wire.push(sig_id);
                }
            }
            
            for sig_id in inputs_to_wire {
                self.add_comp_edge(sig_id, op_id, 0);
            }
            for (sig_id, name_str) in outputs_to_wire {
                self.add_comp_edge(op_id, sig_id, 0);
                // Constraint equivalent for correct phase 2 backwards prop
                let con_id = self.add_node(NodeType::Constraint);
                let proxy_out_id = self.add_node(NodeType::Signal {
                    name: VariableName::from_string(&format!("{}_proxy", name_str)),
                    original_name: "proxy".to_string(),
                    kind: SignalKind::Internal,
                    vis: SignalVis::Pub,
                    inst: prefix.to_string(),
                    location: None,
                    file_id: None
                });
                self.add_comp_edge(op_id, proxy_out_id, 0);
                self.add_con_edge(proxy_out_id, con_id);
                self.add_con_edge(sig_id, con_id);
            }
        }
    }

    fn connect_substitution_summary_edge(
        &mut self,
        scoped_lhs_name: &VariableName,
        lhs_original_name: &str,
        lhs_kind: SignalKind,
        lhs_vis: SignalVis,
        prefix: &str,
        lhs_loc: Option<FileLocation>,
        lhs_file: Option<FileID>,
        rhs_expr: &program_structure::ir::Expression,
        cfg: &program_structure::cfg::Cfg,
    ) {
        let lhs_id = self.get_or_create_var_node(
            scoped_lhs_name,
            lhs_original_name,
            lhs_kind,
            lhs_vis,
            prefix,
            lhs_loc,
            lhs_file,
        );
        let rhs_id = self.process_expression(rhs_expr, cfg, prefix);
        self.add_comp_edge(rhs_id, lhs_id, 0);
        let con_id = self.add_node(NodeType::Constraint);
        self.add_con_edge(lhs_id, con_id);
        self.add_con_edge(rhs_id, con_id);
    }

    fn connect_blackbox_summary_edge(
        &mut self,
        scoped_lhs_name: &VariableName,
        lhs_original_name: &str,
        lhs_kind: SignalKind,
        lhs_vis: SignalVis,
        prefix: &str,
        lhs_loc: Option<FileLocation>,
        lhs_file: Option<FileID>,
        rhs_expr: &program_structure::ir::Expression,
        cfg: &program_structure::cfg::Cfg,
        blackbox_op_type: OpType,
        register_component_ports: bool,
        component_port_hints: Option<ComponentPortHints>,
    ) {
        use program_structure::ir::Expression;

        if let Expression::Call { args, .. } = rhs_expr {
            let lhs_id = self.get_or_create_var_node(
                scoped_lhs_name,
                lhs_original_name,
                lhs_kind,
                lhs_vis,
                prefix,
                lhs_loc,
                lhs_file,
            );

            let op_id = self.add_node(NodeType::Op { op_type: blackbox_op_type });
            if register_component_ports {
                self.abstracted_ops.insert(scoped_lhs_name.name().clone(), op_id);
                if let Some(hints) = component_port_hints {
                    self.component_port_hints.insert(scoped_lhs_name.name().clone(), hints);
                }
            }
            for (idx, arg) in args.iter().enumerate() {
                let arg_id = self.process_expression(arg, cfg, prefix);
                self.add_comp_edge(arg_id, op_id, idx);
            }

            let out_id = self.add_node(NodeType::Signal {
                name: VariableName::from_string("anonymous_out"),
                original_name: "anonymous_out".to_string(),
                kind: SignalKind::Internal,
                vis: SignalVis::Pub,
                inst: prefix.to_string(),
                location: None,
                file_id: None,
            });
            self.add_comp_edge(op_id, out_id, 0);
            self.add_comp_edge(out_id, lhs_id, 0);

            let con_id = self.add_node(NodeType::Constraint);
            self.add_con_edge(lhs_id, con_id);
            self.add_con_edge(out_id, con_id);
            return;
        }

        self.connect_substitution_summary_edge(
            scoped_lhs_name,
            lhs_original_name,
            lhs_kind,
            lhs_vis,
            prefix,
            lhs_loc,
            lhs_file,
            rhs_expr,
            cfg,
        );
    }

    fn extract_component_port_hints(cfg: &program_structure::cfg::Cfg) -> ComponentPortHints {
        use program_structure::ir::{SignalType, VariableType};

        let mut hints = ComponentPortHints::default();
        for (_, decl) in cfg.declarations().iter() {
            if let VariableType::Signal(sig_type, _, _) = decl.variable_type() {
                let base = decl.variable_name().name().to_string();
                match sig_type {
                    SignalType::Input => {
                        hints.input_bases.insert(base);
                    }
                    SignalType::Output => {
                        hints.output_bases.insert(base);
                    }
                    _ => {}
                }
            }
        }
        hints
    }

    fn process_expression(&mut self, expr: &program_structure::ir::Expression, cfg: &program_structure::cfg::Cfg, prefix: &str) -> usize {
        use program_structure::ir::{Expression, ExpressionInfixOpcode, ExpressionPrefixOpcode, AccessType, SignalType, VariableType};

        match expr {
            Expression::Variable { name, .. } => {
                let scoped_name = Self::get_scoped_var_name(name, prefix);
                self.get_or_create_var_node(&scoped_name, name.name(), SignalKind::Internal, SignalVis::Pub, prefix, None, None)
            }
            Expression::Number(..) => {
                let id = self.add_node(NodeType::Signal {
                    name: VariableName::from_string("CONSTANT"),
                    original_name: "CONSTANT".to_string(),
                    kind: SignalKind::Internal,
                    vis: SignalVis::Pub,
                    inst: prefix.to_string(),
                    location: None,
                    file_id: None,
                });
                id
            }
            Expression::InfixOp { lhe, infix_op, rhe, .. } => {
                let lhs_id = self.process_expression(lhe, cfg, prefix);
                let rhs_id = self.process_expression(rhe, cfg, prefix);
                
                let op_type = match infix_op {
                    ExpressionInfixOpcode::Mul | ExpressionInfixOpcode::Div => OpType::Mul,
                    ExpressionInfixOpcode::Add | ExpressionInfixOpcode::Sub => OpType::AddSub,
                    ExpressionInfixOpcode::Eq
                    | ExpressionInfixOpcode::NotEq
                    | ExpressionInfixOpcode::Lesser
                    | ExpressionInfixOpcode::Greater
                    | ExpressionInfixOpcode::LesserEq
                    | ExpressionInfixOpcode::GreaterEq => OpType::Compare,
                    ExpressionInfixOpcode::BitAnd | ExpressionInfixOpcode::ShiftR | ExpressionInfixOpcode::BitOr | ExpressionInfixOpcode::BitXor | ExpressionInfixOpcode::ShiftL => OpType::BitExtract,
                    _ => OpType::Other,
                };

                let op_id = self.add_node(NodeType::Op { op_type });
                self.add_comp_edge(lhs_id, op_id, 0);
                self.add_comp_edge(rhs_id, op_id, 1);
                
                let out_id = self.add_node(NodeType::Signal {
                    name: VariableName::from_string("anonymous_out"),
                    original_name: "anonymous_out".to_string(),
                    kind: SignalKind::Internal,
                    vis: SignalVis::Pub,
                    inst: prefix.to_string(),
                    location: None,
                    file_id: None
                });
                self.add_comp_edge(op_id, out_id, 0);
                out_id
            }
            Expression::PrefixOp { prefix_op, rhe, .. } => {
                let rhs_id = self.process_expression(rhe, cfg, prefix);
                let op_type = match prefix_op {
                    ExpressionPrefixOpcode::Sub => OpType::AddSub,
                    _ => OpType::Other,
                };
                let op_id = self.add_node(NodeType::Op { op_type });
                self.add_comp_edge(rhs_id, op_id, 0);
                
                let out_id = self.add_node(NodeType::Signal {
                    name: VariableName::from_string("anonymous_out"),
                    original_name: "anonymous_out".to_string(),
                    kind: SignalKind::Internal,
                    vis: SignalVis::Pub,
                    inst: prefix.to_string(),
                    location: None,
                    file_id: None
                });
                self.add_comp_edge(op_id, out_id, 0);
                out_id
            }
            Expression::Call { name, args, .. } => {
                let op_type = Self::known_call_op_type(name).unwrap_or(OpType::Other);
                
                let op_id = self.add_node(NodeType::Op { op_type });
                for (i, arg) in args.iter().enumerate() {
                    let arg_id = self.process_expression(arg, cfg, prefix);
                    self.add_comp_edge(arg_id, op_id, i);
                }
                
                let out_id = self.add_node(NodeType::Signal {
                    name: VariableName::from_string("anonymous_out"),
                    original_name: "anonymous_out".to_string(),
                    kind: SignalKind::Internal,
                    vis: SignalVis::Pub,
                    inst: prefix.to_string(),
                    location: None,
                    file_id: None
                });
                self.add_comp_edge(op_id, out_id, 0);
                out_id
            }
            Expression::SwitchOp { cond, if_true, if_false, .. } => {
                let op_id = self.add_node(NodeType::Op { op_type: OpType::Select });
                let cond_id = self.process_expression(cond, cfg, prefix);
                let true_id = self.process_expression(if_true, cfg, prefix);
                let false_id = self.process_expression(if_false, cfg, prefix);
                self.add_comp_edge(cond_id, op_id, 0);
                self.add_comp_edge(true_id, op_id, 1);
                self.add_comp_edge(false_id, op_id, 2);
                
                let out_id = self.add_node(NodeType::Signal {
                    name: VariableName::from_string("anonymous_out"),
                    original_name: "anonymous_out".to_string(),
                    kind: SignalKind::Internal,
                    vis: SignalVis::Pub,
                    inst: prefix.to_string(),
                    location: None,
                    file_id: None
                });
                self.add_comp_edge(op_id, out_id, 0);
                out_id
            }
            Expression::InlineArray { values, .. } => {
                let op_id = self.add_node(NodeType::Op { op_type: OpType::Other });
                for (i, val) in values.iter().enumerate() {
                    let v_id = self.process_expression(val, cfg, prefix);
                    self.add_comp_edge(v_id, op_id, i);
                }
                
                let out_id = self.add_node(NodeType::Signal {
                    name: VariableName::from_string("anonymous_out"),
                    original_name: "anonymous_out".to_string(),
                    kind: SignalKind::Internal,
                    vis: SignalVis::Pub,
                    inst: prefix.to_string(),
                    location: None,
                    file_id: None
                });
                self.add_comp_edge(op_id, out_id, 0);
                out_id
            }
            Expression::Access { var, access, .. } | Expression::Update { var, access, .. } => {
                let base_name = Self::get_scoped_var_name(var, prefix);
                let mut full_name = base_name.name().clone();
                for acc in access {
                    match acc {
                        AccessType::ArrayAccess(box_expr) => {
                            if let Expression::Number(_, num) = box_expr.as_ref() { full_name.push_str(&format!("_{}", num)); } 
                            else { full_name.push_str("_ANY"); }
                        }
                        AccessType::ComponentAccess(sig) => full_name.push_str(&format!("_{}", sig)),
                    }
                }
                let scoped_name = VariableName::from_string(full_name);
                
                let mut rhs_kind = SignalKind::Internal;
                let mut rhs_vis = SignalVis::Pub;
                let mut rhs_loc = None;
                let mut rhs_file = None;
                if let Some(decl) = cfg.declarations().get_declaration(var) {
                    if let VariableType::Signal(sig_type, _, is_priv) = decl.variable_type() {
                        rhs_kind = match sig_type {
                            SignalType::Input => SignalKind::Input,
                            SignalType::Output => SignalKind::Output,
                            _ => SignalKind::Internal,
                        };
                        rhs_vis = if *is_priv { SignalVis::Priv } else { SignalVis::Pub };
                        rhs_loc = Some(decl.file_location());
                        rhs_file = decl.file_id();
                    }
                }
                
                self.get_or_create_var_node(&scoped_name, var.name(), rhs_kind, rhs_vis, prefix, rhs_loc, rhs_file)
            }
            Expression::Phi { args, .. } => {
                let op_id = self.add_node(NodeType::Op { op_type: OpType::Select });
                for (i, arg_name) in args.iter().enumerate() {
                    let scoped_name = Self::get_scoped_var_name(arg_name, prefix);
                    
                    let mut phi_kind = SignalKind::Internal;
                    let mut phi_vis = SignalVis::Pub;
                    let mut phi_loc = None;
                    let mut phi_file = None;
                    if let Some(decl) = cfg.declarations().get_declaration(arg_name) {
                        if let VariableType::Signal(sig_type, _, is_priv) = decl.variable_type() {
                            phi_kind = match sig_type {
                                SignalType::Input => SignalKind::Input,
                                SignalType::Output => SignalKind::Output,
                                _ => SignalKind::Internal,
                            };
                            phi_vis = if *is_priv { SignalVis::Priv } else { SignalVis::Pub };
                            phi_loc = Some(decl.file_location());
                            phi_file = decl.file_id();
                        }
                    }
                    let arg_id = self.get_or_create_var_node(&scoped_name, arg_name.name(), phi_kind, phi_vis, prefix, phi_loc, phi_file);
                    self.add_comp_edge(arg_id, op_id, i);
                }
                
                let out_id = self.add_node(NodeType::Signal {
                    name: VariableName::from_string("anonymous_out"),
                    original_name: "anonymous_out".to_string(),
                    kind: SignalKind::Internal,
                    vis: SignalVis::Pub,
                    inst: prefix.to_string(),
                    location: None,
                    file_id: None
                });
                self.add_comp_edge(op_id, out_id, 0);
                out_id
            }
        }
    }

    /// 执行拓扑排序，获取所有 OpNode 的执行顺序
    fn find_upstream_ops(&self, start_sig_id: usize) -> Vec<usize> {
        let mut ops = Vec::new();
        let mut visited = HashSet::new();
        let mut stack = vec![start_sig_id];
        while let Some(curr) = stack.pop() {
            if !visited.insert(curr) { continue; }
            for (upstream_id, edge_type) in self.backward_edges.get(&curr).cloned().unwrap_or_default() {
                if let EdgeType::CompEdge(_) = edge_type {
                    if matches!(self.nodes[upstream_id].node_type, NodeType::Op { .. }) {
                        ops.push(upstream_id);
                    } else if matches!(self.nodes[upstream_id].node_type, NodeType::Signal { .. }) {
                        stack.push(upstream_id);
                    }
                }
            }
        }
        ops
    }

    fn find_downstream_ops(&self, start_sig_id: usize) -> Vec<usize> {
        let mut ops = Vec::new();
        let mut visited = HashSet::new();
        let mut stack = vec![start_sig_id];
        while let Some(curr) = stack.pop() {
            if !visited.insert(curr) { continue; }
            for (downstream_id, edge_type) in self.forward_edges.get(&curr).cloned().unwrap_or_default() {
                if let EdgeType::CompEdge(_) = edge_type {
                    if matches!(self.nodes[downstream_id].node_type, NodeType::Op { .. }) {
                        ops.push(downstream_id);
                    } else if matches!(self.nodes[downstream_id].node_type, NodeType::Signal { .. }) {
                        stack.push(downstream_id);
                    }
                }
            }
        }
        ops
    }

    /// 执行拓扑排序，获取所有 OpNode 的执行顺序
    fn topological_sort_ops(&self) -> Vec<usize> {
        let mut in_degree: HashMap<usize, usize> = HashMap::new();
        let mut queue: VecDeque<usize> = VecDeque::new();
        let mut sorted_ops = Vec::new();

        for node in &self.nodes {
            if let NodeType::Op { .. } = &node.node_type {
                let mut dep_count = 0;
                for (in_sig_id, edge_type) in self.backward_edges.get(&node.id).cloned().unwrap_or_default() {
                    if let EdgeType::CompEdge(_) = edge_type {
                        dep_count += self.find_upstream_ops(in_sig_id).len();
                    }
                }
                in_degree.insert(node.id, dep_count);
                if dep_count == 0 {
                    queue.push_back(node.id);
                }
            }
        }

        while let Some(op_id) = queue.pop_front() {
            sorted_ops.push(op_id);

            for (out_sig_id, edge_type) in self.forward_edges.get(&op_id).cloned().unwrap_or_default() {
                if let EdgeType::CompEdge(_) = edge_type {
                    for downstream_op_id in self.find_downstream_ops(out_sig_id) {
                        if let Some(deg) = in_degree.get_mut(&downstream_op_id) {
                            *deg -= 1;
                            if *deg == 0 {
                                queue.push_back(downstream_op_id);
                            }
                        }
                    }
                }
            }
        }

        sorted_ops
    }


    /// 强度传递函数：接收各操作数独立的 info_set 列表，内部先做多源并集（⊎），再施加强度变换。
    /// 完整对应论文中的五类传播规则：
    ///   Full/Mixing/Selector (AddSub/Mul/Select/Other)：⊎ 合并后强度透传
    ///   Partial (BitExtract/Compare/LogicGate)：⊎ 合并后 Full → Partial
    ///   OneWay (Hash)：⊎ 合并后全部降级为 OneWay
    fn eval_transfer(op_type: &OpType, per_operand_sets: Vec<HashSet<(usize, Intensity)>>) -> HashSet<(usize, Intensity)> {
        // Step 1：对所有操作数的 info_set 做并集（⊎）
        let combined: HashSet<(usize, Intensity)> = per_operand_sets.into_iter().flatten().collect();

        // Step 2：按 OpType 施加强度变换
        match op_type {
            OpType::AddSub | OpType::Mul | OpType::Select | OpType::Other | OpType::BlackBoxAggressive => {
                // Full / Mixing / Selector：强度不变，直接透传
                combined
            }
            OpType::BitExtract | OpType::Compare | OpType::LogicGate => {
                // Partial：Full 降级为 Partial，OneWay 保留
                combined.into_iter().map(|(w, tau)| {
                    let new_tau = match tau {
                        Intensity::Full => Intensity::Partial,
                        other => other,
                    };
                    (w, new_tau)
                }).collect()
            }
            OpType::Hash | OpType::BlackBoxConservative => {
                // OneWay：所有来源统一降级，单向阻断
                combined.into_iter().map(|(w, _)| (w, Intensity::OneWay)).collect()
            }
        }
    }

    /// 阶段一：前向信息流
    pub fn phase_1_forward_information(&mut self) {

        // 使用 Full 强度初始化私有输入
        for &priv_id in &self.private_inputs {
            if let Some(state) = self.states.get_mut(&priv_id) {
                state.info_set.insert((priv_id, Intensity::Full));
            }
        }

        let ops = self.topological_sort_ops();
        
        let propagate_signals = |states: &mut HashMap<usize, SignalState>, nodes: &Vec<Node>, backward_edges: &HashMap<usize, Vec<(usize, EdgeType)>>, forward_edges: &HashMap<usize, Vec<(usize, EdgeType)>>| {
            let mut changed = true;
            while changed {
                changed = false;
                
                // 1. 在纯粹的 信号 -> 信号 赋值操作 (CompEdge) 间传播
                for node in nodes {
                    if let NodeType::Signal { .. } = &node.node_type {
                        let backward = backward_edges.get(&node.id).cloned().unwrap_or_default();
                        for (src_id, edge_type) in backward {
                            if let EdgeType::CompEdge(_) = edge_type {
                                if let NodeType::Signal { .. } = &nodes[src_id].node_type {
                                    let src_info = states.get(&src_id).unwrap().info_set.clone();
                                    if let Some(state) = states.get_mut(&node.id) {
                                        let pre_len = state.info_set.len();
                                        for info in &src_info {
                                            state.info_set.insert(info.clone());
                                        }
                                        if state.info_set.len() > pre_len {
                                            changed = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                // 2. 在约束边 (Constraint edges) 间传播
                for node in nodes {
                    if let NodeType::Constraint = &node.node_type {
                        let mut all_info = HashSet::new();
                        let bounds = forward_edges.get(&node.id).cloned().unwrap_or_default();
                        for (sig_id, edge_type) in &bounds {
                            if let EdgeType::ConEdge = edge_type {
                                if let Some(state) = states.get(sig_id) {
                                    for info in &state.info_set {
                                        all_info.insert(info.clone());
                                    }
                                }
                            }
                        }
                        for (sig_id, edge_type) in &bounds {
                            if let EdgeType::ConEdge = edge_type {
                                if let Some(state) = states.get_mut(sig_id) {
                                    let pre_len = state.info_set.len();
                                    for info in &all_info {
                                        state.info_set.insert(info.clone());
                                    }
                                    if state.info_set.len() > pre_len {
                                        changed = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        };

        for op_id in ops {
            // 在解析此运算节点的输入之前，始终先进行传递性传播！
            propagate_signals(&mut self.states, &self.nodes, &self.backward_edges, &self.forward_edges);
            
            if let NodeType::Op { op_type } = &self.nodes[op_id].node_type.clone() {
                // 收集各操作数独立的 info_set（不预先合并，由 eval_transfer 内部做 ⊎）
                let mut per_operand_sets: Vec<HashSet<(usize, Intensity)>> = Vec::new();
                let inputs = self.backward_edges.get(&op_id).cloned().unwrap_or_default();
                
                for (in_sig_id, edge_type) in inputs {
                    if let EdgeType::CompEdge(_) = edge_type {
                        if let Some(state) = self.states.get(&in_sig_id) {
                            per_operand_sets.push(state.info_set.clone());
                        }
                    }
                }

                let output_set = Self::eval_transfer(op_type, per_operand_sets);

                let outputs = self.forward_edges.get(&op_id).cloned().unwrap_or_default();
                for (out_sig_id, edge_type) in outputs {
                    if let EdgeType::CompEdge(_) = edge_type {
                        let mut final_output_set = output_set.clone();
                        if let NodeType::Signal { inst, original_name, .. } = &self.nodes[out_sig_id].node_type {
                            let lower_inst = inst.to_lowercase();
                            let lower_name = original_name.to_lowercase();
                            if Self::is_hash_like_signal(&lower_inst, &lower_name) {
                                final_output_set = final_output_set.into_iter().map(|(w, _)| (w, Intensity::OneWay)).collect();
                            }
                        }
                        if let Some(state) = self.states.get_mut(&out_sig_id) {
                            for item in final_output_set.clone() {
                                state.info_set.insert(item);
                            }
                        }
                    }
                }
            }
        }
        
        propagate_signals(&mut self.states, &self.nodes, &self.backward_edges, &self.forward_edges);
    }

    /// 尝试升级Knowledge等级。若产生升级，则返回 true
    fn upgrade_knowledge(&mut self, node_id: usize, new_k: &KnowledgeState) -> bool {
        if let Some(state) = self.states.get_mut(&node_id) {
            if new_k > &state.knowledge {
                state.knowledge = new_k.clone();
                return true;
            }
        }
        false
    }

    fn is_meaningful_cascade_cause_signal(&self, node_id: usize, target_id: usize) -> bool {
        if node_id == target_id {
            return false;
        }
        match &self.nodes[node_id].node_type {
            NodeType::Signal { original_name, .. } => {
                !original_name.starts_with("anonymous_out")
            }
            _ => false,
        }
    }

    fn select_cascade_cause(&self, source_id: usize, target_id: usize) -> Option<usize> {
        if self.is_meaningful_cascade_cause_signal(source_id, target_id) {
            return Some(source_id);
        }

        let mut fk_private_candidates: Vec<usize> = Vec::new();
        let mut private_candidates: Vec<usize> = Vec::new();

        if let Some(source_state) = self.states.get(&source_id) {
            for (priv_id, _) in &source_state.info_set {
                if *priv_id == target_id || !self.private_inputs.contains(priv_id) {
                    continue;
                }
                private_candidates.push(*priv_id);
                if self.get_knowledge(*priv_id) == KnowledgeState::FK {
                    fk_private_candidates.push(*priv_id);
                }
            }
        }

        fk_private_candidates.sort_unstable();
        fk_private_candidates.dedup();
        if let Some(chosen) = fk_private_candidates.first() {
            return Some(*chosen);
        }

        private_candidates.sort_unstable();
        private_candidates.dedup();
        private_candidates.first().copied()
    }

    fn mark_cascade_private_if_needed(&mut self, target_id: usize, source_id: usize, source_from_delta: bool) {
        if !source_from_delta || target_id == source_id || !self.private_inputs.contains(&target_id) {
            return;
        }
        let selected_cause = self.select_cascade_cause(source_id, target_id);
        if let Some(state) = self.states.get_mut(&target_id) {
            state.is_cascade_leak = true;
            if state.cascade_cause.is_none() {
                state.cascade_cause = selected_cause.or(Some(source_id));
            }
        }
    }

    fn upgrade_with_source(
        &mut self,
        target_id: usize,
        new_k: &KnowledgeState,
        source_id: usize,
        source_from_delta: bool,
    ) -> bool {
        let upgraded = self.upgrade_knowledge(target_id, new_k);
        if upgraded {
            self.mark_cascade_private_if_needed(target_id, source_id, source_from_delta);
        }
        upgraded
    }
    
    /// 获取当前等级
    fn get_knowledge(&self, node_id: usize) -> KnowledgeState {
        self.states.get(&node_id).map(|s| s.knowledge.clone()).unwrap_or(KnowledgeState::Unknown)
    }

    fn seed_phase_2_sources(&mut self) -> Vec<usize> {
        let mut seeded = Vec::new();

        let pub_in = self.public_inputs.iter().copied().collect::<Vec<_>>();
        for id in pub_in {
            if self.upgrade_knowledge(id, &KnowledgeState::FK) {
                seeded.push(id);
            }
        }

        let pub_out = self.public_outputs.iter().copied().collect::<Vec<_>>();
        for id in pub_out {
            if self.upgrade_knowledge(id, &KnowledgeState::FK) {
                seeded.push(id);
            }
        }

        seeded.sort_unstable();
        seeded
    }

    fn phase_2_propagate_from_node(&mut self, y_id: usize, source_from_delta: bool, broadcasted_fk: &mut HashSet<usize>) -> HashSet<usize> {
        let y_k = self.get_knowledge(y_id);
        let mut delta = HashSet::new();
        
        if y_k == KnowledgeState::FK && self.private_inputs.contains(&y_id) {
            if broadcasted_fk.insert(y_id) {
                let mut to_enqueue = Vec::new();
                for (&node_id, state) in self.states.iter_mut() {
                    let mut needs_recheck = false;
                    if state.info_set.contains(&(y_id, Intensity::OneWay)) {
                        state.info_set.remove(&(y_id, Intensity::OneWay));
                        state.info_set.insert((y_id, Intensity::Full));
                        needs_recheck = true;
                    } else if state.info_set.iter().any(|(p, _)| *p == y_id) {
                        needs_recheck = true;
                    }
                    if needs_recheck {
                        to_enqueue.push(node_id);
                    }
                }
                for n in to_enqueue {
                    if self.get_knowledge(n) != KnowledgeState::Unknown {
                        delta.insert(n);
                    }
                }
            }
        }

        if y_k != KnowledgeState::Unknown {
            let info_set = self.states.get(&y_id).unwrap().info_set.clone();
            let mut unknown_privs = Vec::new();
            for (p_id, tau) in &info_set {
                if self.get_knowledge(*p_id) != KnowledgeState::FK {
                    unknown_privs.push((*p_id, tau.clone()));
                }
            }
            
            let is_blinded = unknown_privs.len() > 1;
            
            for (p_id, tau) in &info_set {
                if self.get_knowledge(*p_id) == KnowledgeState::FK { continue; }
                match tau {
                    Intensity::Full => {
                        if !is_blinded {
                            if y_k == KnowledgeState::FK {
                                if self.upgrade_with_source(*p_id, &KnowledgeState::FK, y_id, source_from_delta) { delta.insert(*p_id); }
                            } else if y_k == KnowledgeState::PK {
                                if self.upgrade_with_source(*p_id, &KnowledgeState::PK, y_id, source_from_delta) { delta.insert(*p_id); }
                            }
                        }
                    }
                    Intensity::Partial => {
                        if !is_blinded {
                            if self.upgrade_with_source(*p_id, &KnowledgeState::PK, y_id, source_from_delta) { delta.insert(*p_id); }
                        }
                    }
                    Intensity::OneWay => {}
                }
            }
        }

        let bindings = self.backward_edges.get(&y_id).cloned().unwrap_or_default();
        for (src_id, edge_type) in bindings {
            if let EdgeType::CompEdge(_) = edge_type {
                if let NodeType::Signal { .. } = &self.nodes[src_id].node_type {
                        let y_k = self.get_knowledge(y_id);
                        if self.upgrade_with_source(src_id, &y_k, y_id, source_from_delta) {
                            delta.insert(src_id);
                        }
                }
            }
        }

        let out_bindings = self.forward_edges.get(&y_id).cloned().unwrap_or_default();
        for (tgt_id, edge_type) in out_bindings {
            if let EdgeType::CompEdge(_) = edge_type {
                if let NodeType::Signal { .. } = &self.nodes[tgt_id].node_type {
                    let y_k = self.get_knowledge(y_id);
                    if self.upgrade_with_source(tgt_id, &y_k, y_id, source_from_delta) {
                        delta.insert(tgt_id);
                    }
                }
            }
        }

        let all_y_edges = self.forward_edges.get(&y_id).cloned().unwrap_or_default();
        for (constraint_op_id, edge_type) in all_y_edges.clone() {
                if let EdgeType::ConEdge = edge_type {
                    let con_edges = self.forward_edges.get(&constraint_op_id).cloned().unwrap_or_default();
                    for (z_id, z_edge_type) in con_edges {
                        if let EdgeType::ConEdge = z_edge_type {
                            if z_id != y_id && z_id != constraint_op_id {
                                let y_k = self.get_knowledge(y_id);
                                let z_k = self.get_knowledge(z_id);
                                
                                if y_k > z_k { 
                                    if self.upgrade_with_source(z_id, &y_k, y_id, source_from_delta) {
                                        delta.insert(z_id);
                                    }
                                }
                            }
                        }
                    }
                }
        }

        let y_backward_edges = self.backward_edges.get(&y_id).cloned().unwrap_or_default();
        for (op_id, edge_type) in y_backward_edges {
            if let EdgeType::CompEdge(_) = edge_type {
                if let NodeType::Op { op_type: OpType::AddSub } = &self.nodes[op_id].node_type {
                    if self.get_knowledge(y_id) == KnowledgeState::FK {
                        let operands = self.backward_edges.get(&op_id).cloned().unwrap_or_default();
                        let mut fk_operands = Vec::new();
                        let mut unknown_operands = Vec::new();
                        
                        for (x_id, _edge) in operands {
                            if self.get_knowledge(x_id) == KnowledgeState::FK {
                                fk_operands.push(x_id);
                            } else {
                                unknown_operands.push(x_id);
                            }
                        }
                        if unknown_operands.len() == 1 {
                            let target_x = unknown_operands[0];
                            if self.upgrade_with_source(target_x, &KnowledgeState::FK, y_id, source_from_delta) {
                                delta.insert(target_x);
                                if let Some(state) = self.states.get_mut(&target_x) {
                                    state.is_relational_leak = true;
                                }
                            }
                        }
                    }
                }
            }
        }

        let y_forward_edges = self.forward_edges.get(&y_id).cloned().unwrap_or_default();
        for (op_id, edge_type) in y_forward_edges {
            if let EdgeType::CompEdge(_) = edge_type {
                if let NodeType::Op { op_type: OpType::AddSub } = &self.nodes[op_id].node_type {
                    let op_out_edges = self.forward_edges.get(&op_id).cloned().unwrap_or_default();
                    for (t_id, out_edge_type) in op_out_edges {
                        if let EdgeType::CompEdge(_) = out_edge_type {
                            if self.get_knowledge(t_id) == KnowledgeState::FK && self.get_knowledge(y_id) == KnowledgeState::FK {
                                let operands = self.backward_edges.get(&op_id).cloned().unwrap_or_default();
                                for (x_id, _edge) in operands {
                                    if x_id != y_id && self.get_knowledge(x_id) != KnowledgeState::FK {
                                        if matches!(self.nodes[x_id].node_type, NodeType::Signal { .. }) {
                                            if self.upgrade_with_source(x_id, &KnowledgeState::FK, y_id, source_from_delta) {
                                                delta.insert(x_id);
                                                if let Some(state) = self.states.get_mut(&x_id) {
                                                    state.is_relational_leak = true;
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

        delta
    }

    /// 阶段二：约束驱动的后向推断
    pub fn phase_2_backward_inference(&mut self) {
        let mut worklist: VecDeque<(usize, bool)> = self.seed_phase_2_sources().into_iter().map(|id| (id, false)).collect();
        let mut broadcasted_fk = HashSet::new();

        while let Some((y_id, source_from_delta)) = worklist.pop_front() {
            let delta = self.phase_2_propagate_from_node(y_id, source_from_delta, &mut broadcasted_fk);

            for d in delta {
                worklist.push_back((d, true));
            }
        }
    }

    pub fn phase_2_backward_inference_single_pass(&mut self) {
        let mut broadcasted_fk = HashSet::new();

        for y_id in self.seed_phase_2_sources() {
            self.phase_2_propagate_from_node(y_id, false, &mut broadcasted_fk);
        }
    }

    fn post_process_cascade_labels(&mut self) {
        let mut public_nodes = self.public_inputs.iter().copied().collect::<Vec<_>>();
        public_nodes.extend(self.public_outputs.iter().copied());
        public_nodes.sort_unstable();
        public_nodes.dedup();

        let mut fk_private_inputs = self
            .private_inputs
            .iter()
            .copied()
            .filter(|id| self.get_knowledge(*id) == KnowledgeState::FK)
            .collect::<Vec<_>>();
        fk_private_inputs.sort_unstable();
        fk_private_inputs.dedup();

        let private_ids = self.private_inputs.iter().copied().collect::<Vec<_>>();
        for target_id in private_ids {
            if self.get_knowledge(target_id) != KnowledgeState::PK {
                continue;
            }
            if self
                .states
                .get(&target_id)
                .map(|s| s.is_cascade_leak)
                .unwrap_or(false)
            {
                continue;
            }

            let mut chosen_cause = None;
            for cause_id in &fk_private_inputs {
                if *cause_id == target_id {
                    continue;
                }

                let shares_public_observation = public_nodes.iter().any(|pub_id| {
                    self.states
                        .get(pub_id)
                        .map(|state| {
                            let has_target = state
                                .info_set
                                .iter()
                                .any(|(p, tau)| *p == target_id && *tau != Intensity::OneWay);
                            let has_cause = state
                                .info_set
                                .iter()
                                .any(|(p, tau)| *p == *cause_id && *tau != Intensity::OneWay);
                            has_target && has_cause
                        })
                        .unwrap_or(false)
                });

                if shares_public_observation {
                    chosen_cause = Some(*cause_id);
                    break;
                }
            }

            if let Some(cause_id) = chosen_cause {
                if let Some(state) = self.states.get_mut(&target_id) {
                    state.is_cascade_leak = true;
                    if state.cascade_cause.is_none() {
                        state.cascade_cause = Some(cause_id);
                    }
                }
            }
        }
    }

    fn build_vanguard_lite_reports(&self) -> ReportCollection {
        let mut reports = ReportCollection::new();
        let mut suspect_by_private: HashMap<usize, (bool, bool, Intensity)> = HashMap::new();
        let mut public_nodes = self.public_inputs.iter().copied().collect::<HashSet<_>>();
        public_nodes.extend(self.public_outputs.iter().copied());

        let mut mark_suspect = |priv_id: usize, tau: &Intensity, is_constraint: bool, is_dataflow: bool| {
            if !self.private_inputs.contains(&priv_id) || matches!(tau, Intensity::OneWay) {
                return;
            }
            let entry = suspect_by_private
                .entry(priv_id)
                .or_insert((false, false, Intensity::Partial));
            if is_constraint {
                entry.0 = true;
            }
            if is_dataflow {
                entry.1 = true;
            }
            if tau > &entry.2 {
                entry.2 = tau.clone();
            }
        };

        for &priv_id in &self.private_inputs {
            let con_neighbors = self.forward_edges.get(&priv_id).cloned().unwrap_or_default();
            for (constraint_id, edge_type) in con_neighbors {
                if !matches!(edge_type, EdgeType::ConEdge) {
                    continue;
                }
                if !matches!(self.nodes[constraint_id].node_type, NodeType::Constraint) {
                    continue;
                }
                let bounded = self.forward_edges.get(&constraint_id).cloned().unwrap_or_default();
                for (sig_id, con_edge_type) in bounded {
                    if !matches!(con_edge_type, EdgeType::ConEdge) || sig_id == priv_id {
                        continue;
                    }
                    if public_nodes.contains(&sig_id) {
                        mark_suspect(priv_id, &Intensity::Full, true, false);
                        if let Some(state) = self.states.get(&sig_id) {
                            for (src_priv_id, tau) in &state.info_set {
                                if *src_priv_id == priv_id {
                                    mark_suspect(priv_id, tau, true, false);
                                }
                            }
                        }
                    }
                }
            }
        }

        for public_id in &self.public_outputs {
            if let Some(state) = self.states.get(public_id) {
                for (priv_id, tau) in &state.info_set {
                    mark_suspect(*priv_id, tau, false, true);
                }
            }
        }

        let mut reported_locations = HashSet::new();
        for (priv_id, (has_constraint, has_dataflow, intensity)) in suspect_by_private {
            if let NodeType::Signal {
                original_name,
                location,
                file_id,
                ..
            } = &self.nodes[priv_id].node_type
            {
                let mut leak_types = Vec::new();
                if has_constraint {
                    leak_types.push("CONSTRAINT LEAK SUSPECT");
                }
                if has_dataflow {
                    leak_types.push("DATAFLOW LEAK SUSPECT");
                }

                for leak_type in leak_types {
                    let rationale = if leak_type == "CONSTRAINT LEAK SUSPECT" {
                        if intensity == Intensity::Full {
                            String::from("This private input is suspected to leak via direct public constraint coupling under VanguardLite single-circuit analysis.")
                        } else {
                            String::from("This private input is suspected to partially leak via public constraint coupling under VanguardLite single-circuit analysis.")
                        }
                    } else if intensity == Intensity::Full {
                        String::from("This private input is suspected to leak via direct witness/dataflow propagation to public outputs under VanguardLite single-circuit analysis.")
                    } else {
                        String::from("This private input is suspected to partially leak via witness/dataflow propagation to public outputs under VanguardLite single-circuit analysis.")
                    };

                    if let (Some(loc), Some(f_id)) = (location, file_id) {
                        let loc_fingerprint = format!("{:?}_{:?}_{}", f_id, loc, leak_type);
                        if reported_locations.insert(loc_fingerprint) {
                            let mut report = Report::warning(
                                format!("Private Input `{}` has a {} risk mapped to public signals.", original_name, leak_type),
                                ReportCode::CcigLeak
                            );
                            report.add_primary(loc.clone(), *f_id, rationale);
                            reports.push(report);
                        }
                    } else {
                        let report = Report::warning(
                            format!("Private Input `{}` has a {} risk mapped to public signals.", original_name, leak_type),
                            ReportCode::CcigLeak
                        );
                        reports.push(report);
                    }
                }
            }
        }

        reports
    }

    /// 整体分析的入口函数
    pub fn run_ccig_leakage_inference(cfg: &program_structure::cfg::Cfg, public_inputs: &[String]) -> ReportCollection {
        Self::run_ccig_leakage_inference_with_config(cfg, public_inputs, CcigRunConfig::default())
    }

    pub fn run_ccig_leakage_inference_with_config(
        cfg: &program_structure::cfg::Cfg,
        public_inputs: &[String],
        config: CcigRunConfig,
    ) -> ReportCollection {
        let mut reports = ReportCollection::new();
        let mut graph = CcigAnalyzer::new();
        graph.variant = config.variant;

        match config.variant {
            CcigVariant::Full => {}
            CcigVariant::NoUnroll => {}
            CcigVariant::NoUnrollConservative => {}
            CcigVariant::NoUnrollAggressive => {}
            CcigVariant::SinglePass => {}
            CcigVariant::VanguardLite => {}
        }
        
        graph.build_from_cfg(cfg, "");
        
        // 更新顶层公共输入的元数据
        let mut public_input_names = HashSet::new();
        for p in public_inputs {
            public_input_names.insert(VariableName::from_string(p.clone()));
        }

        for node in &mut graph.nodes {
            if let NodeType::Signal { name, original_name, kind, vis, .. } = &mut node.node_type {
                if kind == &mut SignalKind::Input {
                    if public_input_names.contains(name) || public_input_names.iter().any(|p| original_name == p.name()) {
                        *vis = SignalVis::Pub;
                        graph.private_inputs.remove(&node.id);
                        graph.public_inputs.insert(node.id);
                    }
                }
            }
        }
        
        // 确保被显式请求的顶层输出变成 public_outputs（如果没有输出列表有时无法自然地捕获）
        let output_vars = cfg.output_signals();
        for out in output_vars {
            if let Some(&node_id) = graph.var_to_id.get(out) {
                graph.public_outputs.insert(node_id);
            }
        }

        // 运行阶段一
        graph.phase_1_forward_information();

        if graph.variant == CcigVariant::VanguardLite {
            return graph.build_vanguard_lite_reports();
        }

        // 运行阶段二
        match graph.variant {
            CcigVariant::SinglePass => graph.phase_2_backward_inference_single_pass(),
            _ => graph.phase_2_backward_inference(),
        }
        graph.post_process_cascade_labels();

        // 生成报告并按物理位置去重 (防止多维数组的无数个底层元素由于统一溯源到同一个父级语法块而导致刷屏)
        let mut reported_locations = std::collections::HashSet::new();
        
        for &priv_id in &graph.private_inputs {
            let knowledge = graph.get_knowledge(priv_id);
            if knowledge != KnowledgeState::Unknown {
                if let NodeType::Signal { original_name, location, file_id, .. } = &graph.nodes[priv_id].node_type {
                    let is_full = knowledge == KnowledgeState::FK;
                    let (is_relational, is_cascade, cascade_cause) = graph.states.get(&priv_id)
                        .map(|s| (s.is_relational_leak, s.is_cascade_leak, s.cascade_cause))
                        .unwrap_or((false, false, None));
                    let cascade_cause_name = cascade_cause.and_then(|id| match &graph.nodes[id].node_type {
                        NodeType::Signal { original_name, .. } => Some(original_name.clone()),
                        _ => None,
                    });
                    let leak_type = if is_full {
                        if is_cascade {
                            if let Some(cause) = &cascade_cause_name {
                                format!("FULL LEAK (Cascade, caused by `{}`)", cause)
                            } else {
                                String::from("FULL LEAK (Cascade)")
                            }
                        } else if is_relational {
                            String::from("FULL LEAK (Relational De-blinding)")
                        } else {
                            String::from("FULL LEAK")
                        }
                    } else if is_cascade {
                        if let Some(cause) = &cascade_cause_name {
                            format!("PARTIAL LEAK (Cascade, caused by `{}`)", cause)
                        } else {
                            String::from("PARTIAL LEAK (Cascade)")
                        }
                    } else {
                        String::from("PARTIAL LEAK")
                    };
                    
                    if let (Some(loc), Some(f_id)) = (location, file_id) {
                        let loc_fingerprint = format!("{:?}_{:?}_{}", f_id, loc, leak_type);
                        
                        if reported_locations.insert(loc_fingerprint) {
                            let mut report = Report::warning(
                                format!("Private Input `{}` has a {} risk mapped to public outputs.", original_name, leak_type),
                                ReportCode::CcigLeak
                            );
                            
                            let rationale = if is_cascade {
                                if let Some(cause) = cascade_cause_name {
                                    format!("This private input is exposed through cascading disclosure. The disclosure of `{}` triggered additional inference that exposed this signal.", cause)
                                } else {
                                    String::from("This private input is exposed through cascading disclosure triggered by additional inference.")
                                }
                            } else if is_full {
                                String::from("This private input completely leaks its exact value via deterministic relation constraints.")
                            } else {
                                String::from("This private input partially leaks its value, severely restricting its plausible entropy domain.")
                            };

                            report.add_primary(loc.clone(), *f_id, rationale);
                            reports.push(report);
                        }
                    } else {
                        // 对于没有位置映射信息的游离节点，强行输出（不纳入严格位置去重）
                        let report = Report::warning(
                            format!("Private Input `{}` has a {} risk mapped to public outputs.", original_name, leak_type),
                            ReportCode::CcigLeak
                        );
                        reports.push(report);
                    }
                }
            }
        }

        reports
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ccig_construction_and_phases() {
        let src = [r#"
            template Test() {
                signal input private_a; 
                signal input b;
                signal output pub_c; 
                signal intermediate_d;
                
                // private_a 经受加法，被认为是强绑定
                intermediate_d <== private_a + b;
                // d 参与位提取运算被赋值给 pub_c
                pub_c <== intermediate_d & 255; 
            }
        "#];

        let mut context = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        let cfg = context.take_template("Test").unwrap();
        let reports = CcigAnalyzer::run_ccig_leakage_inference(&cfg, &["b".to_string(), "pub_c".to_string()]);
        
        let report_texts: Vec<String> = reports.into_iter().map(|r| r.message().to_string()).collect();
        assert!(report_texts.iter().any(|m| m.contains("Private Input `private_a` has a PARTIAL LEAK risk")));
        assert!(!report_texts.iter().any(|m| m.contains("FULL LEAK risk")));
    }

    #[test]
    fn test_zkleak_full_leak_relational() {
        let src = [r#"
            template RelationalLeak() {
                signal input secret_x; 
                signal input secret_y;
                signal output pub_t; 
                signal output pub_y_copy;
                
                // t = x + y
                pub_t <== secret_x + secret_y;
                pub_y_copy <== secret_y;
            }
        "#];

        let mut context = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        let cfg = context.take_template("RelationalLeak").unwrap();
        let reports = CcigAnalyzer::run_ccig_leakage_inference(&cfg, &["pub_t".to_string(), "pub_y_copy".to_string()]);
        
        let report_texts: Vec<String> = reports.into_iter().map(|r| r.message().to_string()).collect();
        assert!(report_texts.iter().any(|m| m.contains("Private Input `secret_x` has a FULL LEAK (Cascade")), "Found: {:?}", report_texts);
        assert!(report_texts.iter().any(|m| m.contains("caused by `secret_y`")), "Found: {:?}", report_texts);
        assert!(report_texts.iter().any(|m| m.contains("Private Input `secret_y` has a FULL LEAK risk")));
    }

    #[test]
    fn test_regression_natural_public_leak_is_not_marked_as_cascade() {
        let src = [r#"
            template NaturalPublicLeak() {
                signal input secret_y;
                signal output pub_y;
                pub_y <== secret_y;
            }
        "#];

        let mut context = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        let cfg = context.take_template("NaturalPublicLeak").unwrap();
        let reports = CcigAnalyzer::run_ccig_leakage_inference(&cfg, &["pub_y".to_string()]);

        let report_texts: Vec<String> = reports.into_iter().map(|r| r.message().to_string()).collect();
        assert!(report_texts.iter().any(|m| m.contains("Private Input `secret_y` has a FULL LEAK risk")), "Found: {:?}", report_texts);
        assert!(!report_texts.iter().any(|m| m.contains("Private Input `secret_y` has a FULL LEAK (Cascade")), "Found: {:?}", report_texts);
    }

    #[test]
    fn test_regression_delta_reentry_marks_cascade_with_cause() {
        let src = [r#"
            template DeltaCascade() {
                signal input secret_x;
                signal input secret_y;
                signal output pub_sum;
                signal output pub_y;

                pub_sum <== secret_x + secret_y;
                pub_y <== secret_y;
            }
        "#];

        let mut context = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        let cfg = context.take_template("DeltaCascade").unwrap();
        let reports = CcigAnalyzer::run_ccig_leakage_inference(&cfg, &["pub_sum".to_string(), "pub_y".to_string()]);

        let report_texts: Vec<String> = reports.into_iter().map(|r| r.message().to_string()).collect();
        assert!(report_texts.iter().any(|m| m.contains("Private Input `secret_x` has a FULL LEAK (Cascade")), "Found: {:?}", report_texts);
        assert!(report_texts.iter().any(|m| m.contains("Private Input `secret_x` has a FULL LEAK (Cascade") && m.contains("caused by `secret_y`")), "Found: {:?}", report_texts);
    }

    #[test]
    fn test_single_pass_variant_detects_direct_full_leak() {
        let src = [r#"
            template DirectLeak() {
                signal input secret_x;
                signal output pub_out;
                pub_out <== secret_x;
            }
        "#];

        let mut context = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        let cfg = context.take_template("DirectLeak").unwrap();
        let reports = CcigAnalyzer::run_ccig_leakage_inference_with_config(
            &cfg,
            &["pub_out".to_string()],
            CcigRunConfig { variant: CcigVariant::SinglePass },
        );

        let report_texts: Vec<String> = reports.into_iter().map(|r| r.message().to_string()).collect();
        assert!(report_texts.iter().any(|m| m.contains("Private Input `secret_x` has a FULL LEAK risk")));
    }

    #[test]
    fn test_single_pass_variant_relational_chain_less_precise_than_full() {
        let src = [r#"
            template RelationalChain() {
                signal input secret_x;
                signal input secret_y;
                signal output pub_t;
                signal output pub_y_copy;

                pub_t <== secret_x + secret_y;
                pub_y_copy <== secret_y;
            }
        "#];

        let mut context = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        let cfg = context.take_template("RelationalChain").unwrap();

        let full_reports = CcigAnalyzer::run_ccig_leakage_inference_with_config(
            &cfg,
            &["pub_t".to_string(), "pub_y_copy".to_string()],
            CcigRunConfig { variant: CcigVariant::Full },
        );
        let single_pass_reports = CcigAnalyzer::run_ccig_leakage_inference_with_config(
            &cfg,
            &["pub_t".to_string(), "pub_y_copy".to_string()],
            CcigRunConfig { variant: CcigVariant::SinglePass },
        );

        let full_texts: Vec<String> = full_reports.into_iter().map(|r| r.message().to_string()).collect();
        let single_pass_texts: Vec<String> = single_pass_reports.into_iter().map(|r| r.message().to_string()).collect();

        assert!(full_texts.iter().any(|m| m.contains("Private Input `secret_x` has a FULL LEAK")), "full reports: {:?}", full_texts);
        assert!(!single_pass_texts.iter().any(|m| m.contains("Private Input `secret_x` has a FULL LEAK")), "single-pass reports: {:?}", single_pass_texts);
        assert!(single_pass_texts.iter().any(|m| m.contains("Private Input `secret_y` has a FULL LEAK risk")), "single-pass reports: {:?}", single_pass_texts);
    }

    #[test]
    fn test_vanguard_lite_detects_direct_leak_as_suspect() {
        let src = [r#"
            template DirectLeak() {
                signal input secret_x;
                signal output pub_out;
                pub_out <== secret_x;
            }
        "#];

        let mut context = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        let cfg = context.take_template("DirectLeak").unwrap();
        let reports = CcigAnalyzer::run_ccig_leakage_inference_with_config(
            &cfg,
            &["pub_out".to_string()],
            CcigRunConfig { variant: CcigVariant::VanguardLite },
        );

        let report_texts: Vec<String> = reports.into_iter().map(|r| r.message().to_string()).collect();
        assert!(report_texts.iter().any(|m| m.contains("Private Input `secret_x` has a DATAFLOW LEAK SUSPECT risk")), "reports: {:?}", report_texts);
        assert!(report_texts.iter().any(|m| m.contains("Private Input `secret_x` has a CONSTRAINT LEAK SUSPECT risk")), "reports: {:?}", report_texts);
    }

    #[test]
    fn test_vanguard_lite_detects_constraint_suspect_from_public_input_coupling() {
        let src = [r#"
            template ConstraintCoupling() {
                signal input pub_in;
                signal input secret_x;
                pub_in === secret_x;
            }
        "#];

        let mut context = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        let cfg = context.take_template("ConstraintCoupling").unwrap();
        let reports = CcigAnalyzer::run_ccig_leakage_inference_with_config(
            &cfg,
            &["pub_in".to_string()],
            CcigRunConfig { variant: CcigVariant::VanguardLite },
        );

        let report_texts: Vec<String> = reports.into_iter().map(|r| r.message().to_string()).collect();
        assert!(report_texts.iter().any(|m| m.contains("Private Input `secret_x` has a CONSTRAINT LEAK SUSPECT risk")), "reports: {:?}", report_texts);
        assert!(!report_texts.iter().any(|m| m.contains("Private Input `secret_x` has a DATAFLOW LEAK SUSPECT risk")), "reports: {:?}", report_texts);
    }

    #[test]
    fn test_vanguard_lite_hash_path_is_exempted() {
        let src = [r#"
            template SafeHash() {
                signal input secret_x;
                signal output pub_hash;
                pub_hash <== poseidon(secret_x);
            }
        "#];

        let mut context = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        let cfg = context.take_template("SafeHash").unwrap();
        let reports = CcigAnalyzer::run_ccig_leakage_inference_with_config(
            &cfg,
            &["pub_hash".to_string()],
            CcigRunConfig { variant: CcigVariant::VanguardLite },
        );

        assert!(reports.is_empty());
    }

    #[test]
    fn test_vanguard_lite_reports_suspects_without_full_relational_label() {
        let src = [r#"
            template RelationalChain() {
                signal input secret_x;
                signal input secret_y;
                signal output pub_t;
                signal output pub_y_copy;

                pub_t <== secret_x + secret_y;
                pub_y_copy <== secret_y;
            }
        "#];

        let mut context = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        let cfg = context.take_template("RelationalChain").unwrap();
        let reports = CcigAnalyzer::run_ccig_leakage_inference_with_config(
            &cfg,
            &["pub_t".to_string(), "pub_y_copy".to_string()],
            CcigRunConfig { variant: CcigVariant::VanguardLite },
        );

        let report_texts: Vec<String> = reports.into_iter().map(|r| r.message().to_string()).collect();
        assert!(report_texts.iter().any(|m| m.contains("Private Input `secret_y`") && m.contains("LEAK SUSPECT risk")), "reports: {:?}", report_texts);
        assert!(report_texts.iter().any(|m| m.contains("Private Input `secret_x`") && m.contains("LEAK SUSPECT risk")), "reports: {:?}", report_texts);
        assert!(!report_texts.iter().any(|m| m.contains("FULL LEAK (Relational De-blinding)")), "reports: {:?}", report_texts);
    }

    #[test]
    fn test_zkleak_oneway_hash_protection() {
        let src = [r#"
            template SafeHash() {
                signal input secret_x; 
                signal output pub_hash; 
                
                pub_hash <== poseidon(secret_x);
            }
        "#];

        let mut context = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        let cfg = context.take_template("SafeHash").unwrap();
        let reports = CcigAnalyzer::run_ccig_leakage_inference(&cfg, &["pub_hash".to_string()]);
        
        assert!(reports.is_empty());
    }

    #[test]
    fn test_zkleak_subcomponent_leak() {
        let src = [
            r#"
            template Sub() {
                signal input in1;
                signal output out;
                out <== in1;
            }
            "#,
            r#"
            template Main() {
                signal input private_x;
                signal output pub_y;
                component sub = Sub();
                sub.in1 <== private_x;
                pub_y <== sub.out;
            }
            "#
        ];

        let mut runner = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        runner.generate_all_cfgs();
        let cfg_manager = runner.link_all_cfg_references();
        
        let cfg_ref = cfg_manager.get_template_cfg_ref("Main").unwrap();
        let cfg = cfg_ref.borrow();
        let reports = CcigAnalyzer::run_ccig_leakage_inference(&cfg, &["pub_y".to_string()]);
        
        let report_texts: Vec<String> = reports.into_iter().map(|r| r.message().to_string()).collect();
        assert!(report_texts.iter().any(|m| m.contains("Private Input `private_x` has a FULL LEAK risk")));
    }

    #[test]
    fn test_no_unroll_conservative_unknown_template_call_blocks_leakage() {
        let src = [
            r#"
            template Sub() {
                signal input in1;
                signal output out;
                out <== in1;
            }
            "#,
            r#"
            template Main() {
                signal input private_x;
                signal output pub_y;
                component sub = Sub();
                sub.in1 <== private_x;
                pub_y <== sub.out;
            }
            "#
        ];

        let mut runner = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        runner.generate_all_cfgs();
        let cfg_manager = runner.link_all_cfg_references();

        let cfg_ref = cfg_manager.get_template_cfg_ref("Main").unwrap();
        let cfg = cfg_ref.borrow();
        let reports = CcigAnalyzer::run_ccig_leakage_inference_with_config(
            &cfg,
            &["pub_y".to_string()],
            CcigRunConfig { variant: CcigVariant::NoUnrollConservative },
        );

        let report_texts: Vec<String> = reports.into_iter().map(|r| r.message().to_string()).collect();
        assert!(report_texts.is_empty(), "conservative reports: {:?}", report_texts);
    }

    #[test]
    fn test_no_unroll_aggressive_unknown_template_call_propagates_full_source() {
        let src = [
            r#"
            template Sub() {
                signal input in1;
                signal output out;
                out <== in1;
            }
            "#,
            r#"
            template Main() {
                signal input private_x;
                signal output pub_y;
                component sub = Sub();
                sub.in1 <== private_x;
                pub_y <== sub.out;
            }
            "#
        ];

        let mut runner = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        runner.generate_all_cfgs();
        let cfg_manager = runner.link_all_cfg_references();

        let cfg_ref = cfg_manager.get_template_cfg_ref("Main").unwrap();
        let cfg = cfg_ref.borrow();
        let reports = CcigAnalyzer::run_ccig_leakage_inference_with_config(
            &cfg,
            &["pub_y".to_string()],
            CcigRunConfig { variant: CcigVariant::NoUnrollAggressive },
        );

        let report_texts: Vec<String> = reports.into_iter().map(|r| r.message().to_string()).collect();
        assert!(report_texts.iter().any(|m| m.contains("Private Input `private_x` has a FULL LEAK risk")));
    }

    #[test]
    fn test_no_unroll_alias_keeps_conservative_default() {
        let src = [
            r#"
            template Sub() {
                signal input in1;
                signal output out;
                out <== in1;
            }
            "#,
            r#"
            template Main() {
                signal input private_x;
                signal output pub_y;
                component sub = Sub();
                sub.in1 <== private_x;
                pub_y <== sub.out;
            }
            "#
        ];

        let mut runner = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        runner.generate_all_cfgs();
        let cfg_manager = runner.link_all_cfg_references();

        let cfg_ref = cfg_manager.get_template_cfg_ref("Main").unwrap();
        let cfg = cfg_ref.borrow();
        let reports = CcigAnalyzer::run_ccig_leakage_inference_with_config(
            &cfg,
            &["pub_y".to_string()],
            CcigRunConfig { variant: CcigVariant::NoUnroll },
        );

        let report_texts: Vec<String> = reports.into_iter().map(|r| r.message().to_string()).collect();
        assert!(report_texts.is_empty(), "no-unroll alias reports: {:?}", report_texts);
    }

    #[test]
    fn test_full_function_call_links_return_to_lhs() {
        let src = [
            r#"
            function passthrough(v) {
                var t = v;
                return t;
            }
            "#,
            r#"
            template Main() {
                signal input secret;
                signal output pub_out;
                signal output aux;

                pub_out <== passthrough(secret);
                aux <== pub_out;
            }
            "#,
        ];

        let mut runner = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        runner.generate_all_cfgs();
        let cfg_manager = runner.link_all_cfg_references();
        let cfg_ref = cfg_manager.get_template_cfg_ref("Main").unwrap();
        let cfg = cfg_ref.borrow();
        let reports = CcigAnalyzer::run_ccig_leakage_inference_with_config(
            &cfg,
            &["pub_out".to_string(), "aux".to_string()],
            CcigRunConfig { variant: CcigVariant::Full },
        );

        let report_texts: Vec<String> = reports.into_iter().map(|r| r.message().to_string()).collect();
        assert!(report_texts.iter().any(|m| m.contains("Private Input `secret` has a FULL LEAK risk")), "reports: {:?}", report_texts);
    }

    #[test]
    fn test_no_unroll_known_template_abstraction_still_works() {
        let src = [
            r#"
            template LessThan(n) {
                signal input in[2];
                signal output out;
                out <== in[0] - in[1];
            }
            "#,
            r#"
            template IsValid() {
                signal input secret;
                signal input public_threshold;
                signal output isValid;

                component lt = LessThan(64);
                lt.in[0] <== secret;
                lt.in[1] <== public_threshold;
                isValid <== lt.out;
            }
            "#,
        ];

        let mut context = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        let cfg = context.take_template("IsValid").unwrap();
        let reports = CcigAnalyzer::run_ccig_leakage_inference_with_config(
            &cfg,
            &["isValid".to_string(), "public_threshold".to_string()],
            CcigRunConfig { variant: CcigVariant::NoUnroll },
        );

        let report_texts: Vec<String> = reports.into_iter().map(|r| r.message().to_string()).collect();
        assert!(report_texts.iter().any(|m| m.contains("Private Input `secret` has a PARTIAL LEAK risk")));
    }

    #[test]
    fn test_risk2_variants_regression_matrix() {
        let src = [
            r#"
            template WeightSum(n) {
                signal input ai[n];
                signal input ri[n];
                signal output out;

                signal wsum[n];
                wsum[0] <== ai[0] * ri[0];
                for (var i = 1; i < n; i++) {
                    wsum[i] <== wsum[i - 1] + ai[i] * ri[i];
                }
                out <== wsum[n - 1];
            }
            "#,
            r#"
            template Risk2(n) {
                signal input t;
                signal input ai[n];
                signal input ri[n];
                signal output fin;

                var alpha = 5;
                component sum = WeightSum(n);
                sum.ai <== ai;
                sum.ri <== ri;
                fin <== alpha * sum.out / t;
            }
            "#,
        ];

        let mut runner = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        runner.generate_all_cfgs();
        let cfg_manager = runner.link_all_cfg_references();
        let cfg_ref = cfg_manager.get_template_cfg_ref("Risk2").unwrap();
        let cfg = cfg_ref.borrow();

        let full_reports = CcigAnalyzer::run_ccig_leakage_inference_with_config(
            &cfg,
            &["fin".to_string()],
            CcigRunConfig { variant: CcigVariant::Full },
        );
        let conservative_reports = CcigAnalyzer::run_ccig_leakage_inference_with_config(
            &cfg,
            &["fin".to_string()],
            CcigRunConfig { variant: CcigVariant::NoUnrollConservative },
        );
        let aggressive_reports = CcigAnalyzer::run_ccig_leakage_inference_with_config(
            &cfg,
            &["fin".to_string()],
            CcigRunConfig { variant: CcigVariant::NoUnrollAggressive },
        );
        let single_pass_reports = CcigAnalyzer::run_ccig_leakage_inference_with_config(
            &cfg,
            &["fin".to_string()],
            CcigRunConfig { variant: CcigVariant::SinglePass },
        );
        let vanguard_reports = CcigAnalyzer::run_ccig_leakage_inference_with_config(
            &cfg,
            &["fin".to_string()],
            CcigRunConfig { variant: CcigVariant::VanguardLite },
        );

        let full_texts: Vec<String> = full_reports.into_iter().map(|r| r.message().to_string()).collect();
        let conservative_texts: Vec<String> = conservative_reports.into_iter().map(|r| r.message().to_string()).collect();
        let aggressive_texts: Vec<String> = aggressive_reports.into_iter().map(|r| r.message().to_string()).collect();
        let single_pass_texts: Vec<String> = single_pass_reports.into_iter().map(|r| r.message().to_string()).collect();
        let vanguard_texts: Vec<String> = vanguard_reports.into_iter().map(|r| r.message().to_string()).collect();

        assert!(full_texts.is_empty(), "full reports: {:?}", full_texts);
        assert!(conservative_texts.is_empty(), "conservative reports: {:?}", conservative_texts);
        assert!(
            aggressive_texts.iter().any(|m| m.contains("Private Input `t` has a FULL LEAK risk")),
            "aggressive reports: {:?}",
            aggressive_texts
        );
        assert!(single_pass_texts.is_empty(), "single-pass reports: {:?}", single_pass_texts);
        assert!(
            vanguard_texts.iter().any(|m| m.contains("Private Input `t` has a DATAFLOW LEAK SUSPECT risk")),
            "vanguard-lite reports: {:?}",
            vanguard_texts
        );
        assert!(
            conservative_texts.iter().all(|m| !m.contains("`ai`") && !m.contains("`ri`")),
            "conservative reports: {:?}",
            conservative_texts
        );
        assert!(
            aggressive_texts.iter().all(|m| !m.contains("`ai`") && !m.contains("`ri`")),
            "aggressive reports: {:?}",
            aggressive_texts
        );
    }

    #[test]
    fn test_zkleak_basic_arithmetic() {
        let src = [r#"
            template Arithmetic() {
                signal input p_x;
                signal input p_y;
                signal input pub_a;
                signal output out;
                
                // 复杂算术关系应该全额转移 Full 强度
                out <== (p_x * p_y) - (pub_a / 2) + (p_x ** 2);
            }
        "#];

        let mut context = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        let cfg = context.take_template("Arithmetic").unwrap();
        let reports = CcigAnalyzer::run_ccig_leakage_inference(&cfg, &["pub_a".to_string(), "out".to_string()]);
        
        let report_texts: Vec<String> = reports.into_iter().map(|r| r.message().to_string()).collect();
        // Since p_x and p_y are mixed creating algebraic blinding, their status remains safe (\bot).
        assert!(!report_texts.iter().any(|m| m.contains("Private Input `p_x` has a FULL LEAK risk")));
        assert!(!report_texts.iter().any(|m| m.contains("Private Input `p_y` has a FULL LEAK risk")));
    }

    #[test]
    fn test_zkleak_bitwise_operations() {
        let src = [r#"
            template Bitwise() {
                signal input secret_val;
                signal output exact_out;
                signal output masked_out;
                
                // 先验证位移等造成降级
                signal temp;
                temp <== secret_val >> 4;
                masked_out <== temp & 0xFF;
            }
        "#];

        let mut context = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        let cfg = context.take_template("Bitwise").unwrap();
        let reports = CcigAnalyzer::run_ccig_leakage_inference(&cfg, &["exact_out".to_string(), "masked_out".to_string()]);
        
        let report_texts: Vec<String> = reports.into_iter().map(|r| r.message().to_string()).collect();
        // 因为涉及位操作，应该准确降级为 Partial
        assert!(report_texts.iter().any(|m| m.contains("Private Input `secret_val` has a PARTIAL LEAK risk")));
        assert!(!report_texts.iter().any(|m| m.contains("FULL LEAK risk")));
    }

    #[test]
    fn test_zkleak_transitive_alias() {
        let src = [r#"
            template TransitiveAliases() {
                signal input secret_val;
                signal output pub_out;
                
                signal intermediate_1;
                signal intermediate_2;
                
                // 纯信号传递/别名
                intermediate_1 <== secret_val;
                intermediate_2 <== intermediate_1;
                pub_out <== intermediate_2;
            }
        "#];

        let mut context = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        let cfg = context.take_template("TransitiveAliases").unwrap();
        let reports = CcigAnalyzer::run_ccig_leakage_inference(&cfg, &["pub_out".to_string()]);
        
        let report_texts: Vec<String> = reports.into_iter().map(|r| r.message().to_string()).collect();
        // 传递别名不改变泄漏等级，源头依然是 Full
        assert!(report_texts.iter().any(|m| m.contains("Private Input `secret_val` has a FULL LEAK risk")));
    }
    #[test]
    fn test_zkleak_confidential_bonus_claim() {
        // This test models the Confidential Bonus Claim circuit from the paper's walkthrough.
        // It demonstrates:
        // 1. Un-invertible cryptographic hashing preventing leakage.
        // 2. Intra-circuit Full Leakage via an exposed invertible Affine relationship.
        // 3. Inter-circuit Cascading Partial Leakage triggered by relational de-blinding.
        let src = [
            r#"
            template Poseidon(n) {
                signal input inputs[n];
                signal output out;
                out <== inputs[0] + 1; // Fake mock implementation
            }
            "#,
            r#"
            template LessThan(n) {
                signal input in[2];
                signal output out;
                out <== in[0] - in[1]; // Fake mock implementation
            }
            "#,
            r#"
            template CheckEligibility() {
                signal input totalScore;
                signal input thresh;
                signal output isElig;

                component lt = LessThan(64);
                lt.in[0] <== totalScore;
                lt.in[1] <== thresh;
                isElig <== lt.out;
            }
            "#,
            r#"
            template BonusClaim() {
                // Private inputs
                signal input balance;
                signal input creditScore;
                // Public inputs
                signal input commit;
                signal input mult;
                signal input thresh;

                // Public outputs
                signal output bonus;
                signal output isElig;
                signal output totalScore; // Explicitly declared as output

                // 1. Integrity Check (OneWay)
                component h = Poseidon(1);
                h.inputs[0] <== balance;
                commit === h.out;

                // 2. Intra-circuit Full Leakage
                bonus <-- mult * balance + 1;
                bonus === mult * balance + 1;

                // 3. Inter-circuit Cascading Partial Leakage
                totalScore <== balance + creditScore;
                component ce = CheckEligibility();
                ce.totalScore <== totalScore;
                ce.thresh <== thresh;
                isElig <== ce.isElig;
            }
            "#,
        ];

        let mut context = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        let cfg = context.take_template("BonusClaim").unwrap();
        let reports = CcigAnalyzer::run_ccig_leakage_inference(&cfg, &["commit".to_string(), "mult".to_string(), "thresh".to_string(), "bonus".to_string(), "isElig".to_string(), "totalScore".to_string()]);
        
        let report_texts: Vec<String> = reports.into_iter().map(|r| r.message().to_string()).collect();

        // 1. `balance` is exposed fully via the affine relation with `bonus`
        assert!(report_texts.iter().any(|m| m.contains("Private Input `balance` has a FULL LEAK risk")));

        // 2. `creditScore` gets relationally de-blinded because `totalScore` is a public output (FK)
        // AND `balance` became FK (from the bonus constraint). Thus, `creditScore` also becomes FK!
        // NOTE: In the paper's narrative, `totalScore` being exposed implies full leakage if `balance` is known.
        // Wait, does our tool correctly flag it as FULL LEAK because of relational deblinding? Yes!
        assert!(report_texts.iter().any(|m| m.contains("Private Input `creditScore` has a FULL LEAK")), "Found: {:?}", report_texts);
    }

    #[test]
    fn test_partial_blinded() {
        let src = [
            r#"
            template LessThan(n) {
                signal input in[2];
                signal output out;
                out <== in[0] - in[1]; // Fake mock implementation
            }
            "#,
            r#"
            template IsValid() {
                signal input secret_a;
                signal input secret_b;
                signal output isValid;

                component lt = LessThan(64);
                lt.in[0] <== secret_a;
                lt.in[1] <== secret_b;
                isValid <== lt.out;
            }
            "#,
        ];

        let mut context = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        let cfg = context.take_template("IsValid").unwrap();
        // isValid is public output
        let reports = CcigAnalyzer::run_ccig_leakage_inference(&cfg, &["isValid".to_string()]);
        
        let report_texts: Vec<String> = reports.into_iter().map(|r| r.message().to_string()).collect();

        // Since secret_a and secret_b are both completely unknown and merged into a Partial relation (LessThan),
        // they blind each other. Neither should be upgraded to PK. So zero leak warnings should be emitted.
        assert!(report_texts.is_empty(), "Expected no leakage because secret_a and secret_b blind each other. Found: {:?}", report_texts);
    }

    #[test]
    fn test_true_partial_leak() {
        let src = [
            r#"
            template LessThan(n) {
                signal input in[2];
                signal output out;
                out <== in[0] - in[1]; // Fake mock implementation
            }
            "#,
            r#"
            template TruePartialLeak() {
                signal input secret;
                signal input public_threshold; // FK
                signal output isValid;

                component lt = LessThan(64);
                lt.in[0] <== secret;
                lt.in[1] <== public_threshold;
                isValid <== lt.out;
            }
            "#,
        ];

        let mut context = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        let cfg = context.take_template("TruePartialLeak").unwrap();
        
        // This test simulates a true partial leak since public_threshold is FK,
        // leaving ONLY secret as the unknown variable in the relation.
        let reports = CcigAnalyzer::run_ccig_leakage_inference(&cfg, &["isValid".to_string(), "public_threshold".to_string()]);
        
        let report_texts: Vec<String> = reports.into_iter().map(|r| r.message().to_string()).collect();

        // `secret` should NOT be blinded since the other operand is a public input (FK).
        // It should be upgraded to PK.
        assert!(report_texts.iter().any(|m| m.contains("Private Input `secret` has a PARTIAL LEAK risk")), "Found: {:?}", report_texts);
    }

    #[test]
    fn test_infix_not_eq_does_not_trigger_full_deblinding_chain() {
        let src = [r#"
            template Biolock() {
                signal input entropy;
                signal input salt;
                signal output uniquenessFlag;
                signal output saltedEntropy;

                uniquenessFlag <== entropy != 0;
                saltedEntropy <== entropy + salt;
            }
        "#];

        let mut context = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        let cfg = context.take_template("Biolock").unwrap();
        let reports = CcigAnalyzer::run_ccig_leakage_inference(&cfg, &["uniquenessFlag".to_string(), "saltedEntropy".to_string()]);

        let report_texts: Vec<String> = reports.into_iter().map(|r| r.message().to_string()).collect();
        assert!(report_texts.iter().any(|m| m.contains("Private Input `entropy` has a PARTIAL LEAK risk")), "reports: {:?}", report_texts);
        assert!(!report_texts.iter().any(|m| m.contains("Private Input `entropy` has a FULL LEAK risk")), "reports: {:?}", report_texts);
        assert!(!report_texts.iter().any(|m| m.contains("Private Input `salt` has a FULL LEAK risk")), "reports: {:?}", report_texts);
    }

    #[test]
    fn test_infix_compare_family_is_partial() {
        let src = [r#"
            template CompareFamily() {
                signal input secret;
                signal output out_lt;
                signal output out_gt;
                signal output out_eq;

                out_lt <== secret < 7;
                out_gt <== secret > 3;
                out_eq <== secret == 5;
            }
        "#];

        let mut context = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        let cfg = context.take_template("CompareFamily").unwrap();
        let reports = CcigAnalyzer::run_ccig_leakage_inference(&cfg, &["out_lt".to_string(), "out_gt".to_string(), "out_eq".to_string()]);

        let report_texts: Vec<String> = reports.into_iter().map(|r| r.message().to_string()).collect();
        assert!(report_texts.iter().any(|m| m.contains("Private Input `secret` has a PARTIAL LEAK risk")), "reports: {:?}", report_texts);
        assert!(!report_texts.iter().any(|m| m.contains("Private Input `secret` has a FULL LEAK risk")), "reports: {:?}", report_texts);
    }

    #[test]
    fn test_ast_sum_nodes_dump() {
        let src = [
        r#"
        template sumMerkleTree(levels) {
            var inputs = 2 ** levels;
            signal input balance[inputs];
            signal input userHash[inputs];
            signal output sum;
            signal output rootHash;

            signal sumNodes[levels + 1][inputs];
            signal hashNodes[levels + 1][inputs];
        }
        "#
        ];
        let mut runner = crate::analysis_runner::AnalysisRunner::new(program_structure::constants::Curve::Goldilocks).with_src(&src);
        runner.generate_all_cfgs();
        let cfg_manager = runner.link_all_cfg_references();

        let cfg_ref = cfg_manager.get_template_cfg_ref("sumMerkleTree").unwrap();
        let cfg = cfg_ref.borrow();
        
        for bb in cfg.iter() {
            for stmt in bb.iter() {
                if let program_structure::ir::Statement::Declaration { names, var_type, .. } = stmt {
                    for name in names {
                        if name.name().contains("sumNodes") || name.name().contains("hashNodes") || name.name().contains("balance") {
                            let mut t = "Other";
                            let mut is_private = false;
                            if let program_structure::ir::VariableType::Signal(st, _, is_p) = var_type {
                                t = match st {
                                    program_structure::ir::SignalType::Input => "Input",
                                    program_structure::ir::SignalType::Output => "Output",
                                    program_structure::ir::SignalType::Intermediate => "Intermediate",
                                };
                                is_private = *is_p;
                            }
                            println!("AST Decl {}: {} (is_priv={})", name.name(), t, is_private);
                        }
                    }
                }
            }
        }
    }
}
