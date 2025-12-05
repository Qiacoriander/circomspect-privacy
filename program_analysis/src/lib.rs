use analysis_context::AnalysisContext;

use program_structure::cfg::Cfg;
use program_structure::report::ReportCollection;

extern crate num_bigint_dig as num_bigint;

pub mod constraint_analysis;
pub mod taint_analysis;
pub mod privacy_taint;
pub mod analysis_context;
pub mod analysis_runner;
pub mod cfg_manager;
pub mod config;

// Intra-process analysis passes.
mod bitwise_complement;
mod bn254_specific_circuit;
mod constant_conditional;
mod definition_complexity;
mod field_arithmetic;
mod field_comparisons;
mod nonstrict_binary_conversion;
mod under_constrained_signals;
mod unconstrained_less_than;
mod unconstrained_division;
mod side_effect_analysis;
mod signal_assignments;

// Inter-process analysis passes.
mod unused_output_signal;

/// An analysis pass is a function which takes an analysis context and a CFG and
/// returns a set of reports.
type AnalysisPass = dyn Fn(&mut dyn AnalysisContext, &Cfg) -> ReportCollection;

/// 分析过程在此注册
/// Box<T>是一个智能指针，它可以在堆上分配内存并存储一个类型为T的值。很大的数据结构or编译期无法确认大小可以用它
pub fn get_analysis_passes() -> Vec<Box<AnalysisPass>> {
    vec![
        // Privacy taint analysis (with leak detection and reports)
        Box::new(|_, cfg| privacy_taint::find_privacy_taint_leaks(cfg)),
        // Intra-process analysis passes.进程内 分析器
        Box::new(|_, cfg| bitwise_complement::find_bitwise_complement(cfg)), // 分析按位取反操作(~x)可能导致的问题
        Box::new(|_, cfg| signal_assignments::find_signal_assignments(cfg)), // 分析信号赋值操作(<--)可能导致的问题
        Box::new(|_, cfg| definition_complexity::run_complexity_analysis(cfg)), // 分析函数或模板的复杂度，比如函数或模板的参数数量是否过多
        Box::new(|_, cfg| side_effect_analysis::run_side_effect_analysis(cfg)), // 分析可能存在的副作用，比如未使用的变量值、未约束的信号
        Box::new(|_, cfg| field_arithmetic::find_field_element_arithmetic(cfg)), // 分析域元素运算可能导致的溢出问题
        Box::new(|_, cfg| field_comparisons::find_field_element_comparisons(cfg)), // 分析域元素比较操作可能导致的问题
        Box::new(|_, cfg| unconstrained_division::find_unconstrained_division(cfg)), // 分析包含除法的信号赋值
        Box::new(|_, cfg| bn254_specific_circuit::find_bn254_specific_circuits(cfg)), // 分析bn254特定电路相关问题，检查是否使用了可能在特定曲线上有问题的模板
        Box::new(|_, cfg| unconstrained_less_than::find_unconstrained_less_than(cfg)), // 分析`LessThan`操作的输入约束
        Box::new(|_, cfg| constant_conditional::find_constant_conditional_statement(cfg)), // 分析条件语句中的常量条件
        Box::new(|_, cfg| under_constrained_signals::find_under_constrained_signals(cfg)), // 分析中间信号的约束情况
        Box::new(|_, cfg| nonstrict_binary_conversion::find_nonstrict_binary_conversion(cfg)), // 分析非严格二进制转换操作可能导致的问题
        // Inter-process analysis passes.进程间 分析器
        Box::new(unused_output_signal::find_unused_output_signals), // 分析未使用的输出信号
    ]
}
