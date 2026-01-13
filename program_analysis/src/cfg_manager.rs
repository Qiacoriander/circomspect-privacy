use std::collections::HashMap;
use std::rc::Rc;
use std::cell::RefCell;
use log::{debug, trace};

use program_structure::cfg::Cfg;
use program_structure::ir::{Statement, Expression, WeakCfgRef};
use program_structure::ssa::traits::SSABasicBlock;

/// 共享的 CFG 引用
pub type CfgRef = Rc<RefCell<Cfg>>;

/// CFG 管理器：管理所有 CFG 引用并为调用表达式建立链接
pub struct CfgManager {
    /// 模板 CFG（共享引用）
    template_cfgs: HashMap<String, CfgRef>,
    /// 函数 CFG（共享引用）
    function_cfgs: HashMap<String, CfgRef>,
}

impl CfgManager {
    /// 创建一个新的 CFG 管理器
    pub fn new() -> Self {
        Self { template_cfgs: HashMap::new(), function_cfgs: HashMap::new() }
    }

    /// 将模板 CFG 添加到管理器
    pub fn add_template_cfg(&mut self, name: String, cfg: Cfg) {
        let cfg_ref = Rc::new(RefCell::new(cfg));
        self.template_cfgs.insert(name, cfg_ref);
    }

    /// 将函数 CFG 添加到管理器
    pub fn add_function_cfg(&mut self, name: String, cfg: Cfg) {
        let cfg_ref = Rc::new(RefCell::new(cfg));
        self.function_cfgs.insert(name, cfg_ref);
    }

    /// 获取模板 CFG 的弱引用
    pub fn get_template_cfg(&self, name: &str) -> Option<WeakCfgRef> {
        self.template_cfgs.get(name).map(|cfg| Rc::downgrade(cfg))
    }

    /// 获取函数 CFG 的弱引用
    pub fn get_function_cfg(&self, name: &str) -> Option<WeakCfgRef> {
        self.function_cfgs.get(name).map(|cfg| Rc::downgrade(cfg))
    }

    /// 获取模板 CFG 的强引用（内部使用）
    pub fn get_template_cfg_ref(&self, name: &str) -> Option<&CfgRef> {
        self.template_cfgs.get(name)
    }

    /// 获取函数 CFG 的强引用（内部使用）
    pub fn get_function_cfg_ref(&self, name: &str) -> Option<&CfgRef> {
        self.function_cfgs.get(name)
    }

    /// 取得模板 CFG 的所有权（并从管理器移除）
    pub fn take_template_cfg(&mut self, name: &str) -> Option<Cfg> {
        self.template_cfgs.remove(name).and_then(|cfg_ref| {
            match Rc::try_unwrap(cfg_ref) {
                Ok(cell) => Some(cell.into_inner()),
                Err(_) => {
                    // 仍存在对此 CFG 的引用，无法取得所有权
                    debug!(
                        "Cannot take ownership of template CFG '{}' - still has references",
                        name
                    );
                    None
                }
            }
        })
    }

    /// 取得函数 CFG 的所有权（并从管理器移除）
    pub fn take_function_cfg(&mut self, name: &str) -> Option<Cfg> {
        self.function_cfgs.remove(name).and_then(|cfg_ref| {
            match Rc::try_unwrap(cfg_ref) {
                Ok(cell) => Some(cell.into_inner()),
                Err(_) => {
                    // 仍存在对此 CFG 的引用，无法取得所有权
                    debug!(
                        "Cannot take ownership of function CFG '{}' - still has references",
                        name
                    );
                    None
                }
            }
        })
    }

    /// 将所有调用表达式链接到其目标 CFG
    /// 应在所有 CFG 加入管理器后调用
    pub fn link_call_references(&mut self) {
        debug!(
            "Linking call references for {} templates and {} functions",
            self.template_cfgs.len(),
            self.function_cfgs.len()
        );

        // 链接模板 CFG 中的调用
        let template_names: Vec<String> = self.template_cfgs.keys().cloned().collect();
        for name in template_names {
            if let Some(cfg_ref) = self.template_cfgs.get(&name) {
                self.link_cfg_calls(cfg_ref);
            }
        }

        // 链接函数 CFG 中的调用
        let function_names: Vec<String> = self.function_cfgs.keys().cloned().collect();
        for name in function_names {
            if let Some(cfg_ref) = self.function_cfgs.get(&name) {
                self.link_cfg_calls(cfg_ref);
            }
        }

        debug!("Finished linking call references");
    }

    /// 为指定的 CFG 链接调用表达式
    fn link_cfg_calls(&self, cfg_ref: &CfgRef) {
        let mut cfg = cfg_ref.borrow_mut();
        let cfg_name = cfg.name().to_string();
        trace!("Linking calls in CFG '{}'", cfg_name);

        for block in cfg.iter_mut() {
            for stmt in block.statements_mut() {
                self.link_statement_calls(stmt);
            }
        }
    }

    /// 递归为语句中的调用表达式建立链接
    fn link_statement_calls(&self, stmt: &mut Statement) {
        use Statement::*;
        match stmt {
            Declaration { dimensions, .. } => {
                for dim in dimensions {
                    self.link_expression_calls(dim);
                }
            }
            IfThenElse { cond, .. } => {
                self.link_expression_calls(cond);
            }
            Return { value, .. } => {
                self.link_expression_calls(value);
            }
            Substitution { rhe, .. } => {
                self.link_expression_calls(rhe);
            }
            ConstraintEquality { lhe, rhe, .. } => {
                self.link_expression_calls(lhe);
                self.link_expression_calls(rhe);
            }
            LogCall { args, .. } => {
                use program_structure::ir::LogArgument;
                for arg in args {
                    if let LogArgument::Expr(expr) = arg {
                        self.link_expression_calls(expr);
                    }
                }
            }
            Assert { arg, .. } => {
                self.link_expression_calls(arg);
            }
        }
    }

    /// 递归为表达式中的调用表达式建立链接
    fn link_expression_calls(&self, expr: &mut Expression) {
        use Expression::*;
        match expr {
            InfixOp { lhe, rhe, .. } => {
                self.link_expression_calls(lhe);
                self.link_expression_calls(rhe);
            }
            PrefixOp { rhe, .. } => {
                self.link_expression_calls(rhe);
            }
            SwitchOp { cond, if_true, if_false, .. } => {
                self.link_expression_calls(cond);
                self.link_expression_calls(if_true);
                self.link_expression_calls(if_false);
            }
            Call { name, args, target_cfg, .. } => {
                // 先链接参数中的调用
                for arg in args {
                    self.link_expression_calls(arg);
                }

                // 尝试查找目标 CFG
                if target_cfg.is_none() {
                    // 优先按模板查找
                    if let Some(weak_ref) = self.get_template_cfg(name) {
                        *target_cfg = Some(weak_ref);
                        trace!("Linked call to template '{}'", name);
                    }
                    // 其次按函数查找
                    else if let Some(weak_ref) = self.get_function_cfg(name) {
                        *target_cfg = Some(weak_ref);
                        trace!("Linked call to function '{}'", name);
                    } else {
                        trace!("Could not find target CFG for call to '{}'", name);
                    }
                }
            }
            InlineArray { values, .. } => {
                for value in values {
                    self.link_expression_calls(value);
                }
            }
            Access { access, .. } => {
                use program_structure::ir::AccessType;
                for acc in access {
                    if let AccessType::ArrayAccess(expr) = acc {
                        self.link_expression_calls(expr);
                    }
                }
            }
            Update { access, rhe, .. } => {
                use program_structure::ir::AccessType;
                for acc in access {
                    if let AccessType::ArrayAccess(expr) = acc {
                        self.link_expression_calls(expr);
                    }
                }
                self.link_expression_calls(rhe);
            }
            // 这些表达式不包含需要链接的子表达式
            Variable { .. } | Number(..) | Phi { .. } => {}
        }
    }

    /// 获取所有模板名称
    pub fn template_names(&self) -> Vec<&String> {
        self.template_cfgs.keys().collect()
    }

    /// 获取所有函数名称
    pub fn function_names(&self) -> Vec<&String> {
        self.function_cfgs.keys().collect()
    }

    /// 检查模板是否存在
    pub fn has_template(&self, name: &str) -> bool {
        self.template_cfgs.contains_key(name)
    }

    /// 检查函数是否存在
    pub fn has_function(&self, name: &str) -> bool {
        self.function_cfgs.contains_key(name)
    }
}

impl Default for CfgManager {
    fn default() -> Self {
        Self::new()
    }
}
