use super::ast::Definition;
use super::report_code::ReportCode;
use super::report::Report;
use super::file_definition::FileID;
use super::function_data::{FunctionData, FunctionInfo};
use super::template_data::{TemplateData, TemplateInfo};

/// 负责将输入的好几个不同文件中的定义(函数&模板)合并到一个统一的结构中
#[derive(Default)]
pub struct Merger {
    fresh_id: usize,
    function_info: FunctionInfo, // 实际上是 HashMap<String, FunctionData>， key为function name
    template_info: TemplateInfo, // 实际上是 HashMap<String, TemplateData>， key为template name
}

impl Merger {
    pub fn new() -> Merger {
        Merger::default()
    }

    /// 这个方法的工作流程是：
    /// 1.遍历传入的定义列表
    /// 2.对于每个定义（可能是函数或模板）：
    ///     - 检查是否已经存在同名的函数或模板（通过 contains_function 和 contains_template 方法）
    ///     - 如果不存在，则创建相应的 FunctionData 或 TemplateData 对象，并将其添加到 function_info 或 template_info 中
    ///     - 如果已存在，则记录一个错误报告（重复定义错误）
    /// 3. 如果没有错误，返回 Ok(()) ；否则返回包含所有错误的 Err(reports)
    pub fn add_definitions(
        &mut self,
        file_id: FileID,
        definitions: &Vec<Definition>,
    ) -> Result<(), Vec<Report>> {
        let mut reports = vec![];
        for definition in definitions {
            let (name, meta) = match definition {
                Definition::Template {
                    name,
                    args,
                    arg_location,
                    body,
                    meta,
                    parallel,
                    is_custom_gate,
                } => {
                    if self.contains_function(name) || self.contains_template(name) {
                        (Option::Some(name), meta)
                    } else {
                        let new_data = TemplateData::new(
                            name.clone(),
                            file_id,
                            body.clone(),
                            args.len(),
                            args.clone(),
                            arg_location.clone(),
                            &mut self.fresh_id,
                            *parallel,
                            *is_custom_gate,
                        );
                        self.get_mut_template_info().insert(name.clone(), new_data);
                        (Option::None, meta)
                    }
                }
                Definition::Function { name, body, args, arg_location, meta } => {
                    if self.contains_function(name) || self.contains_template(name) {
                        (Option::Some(name), meta)
                    } else {
                        let new_data = FunctionData::new(
                            name.clone(),
                            file_id,
                            body.clone(),
                            args.len(),
                            args.clone(),
                            arg_location.clone(),
                            &mut self.fresh_id,
                        );
                        self.get_mut_function_info().insert(name.clone(), new_data);
                        (Option::None, meta)
                    }
                }
            };
            if let Option::Some(definition_name) = name {
                let mut report = Report::error(
                    String::from("Duplicated function or template."),
                    ReportCode::SameSymbolDeclaredTwice,
                );
                report.add_primary(
                    meta.file_location(),
                    file_id,
                    format!("The name `{definition_name}` is already used."),
                );
                reports.push(report);
            }
        }
        if reports.is_empty() {
            Ok(())
        } else {
            Err(reports)
        }
    }
    pub fn contains_function(&self, function_name: &str) -> bool {
        self.get_function_info().contains_key(function_name)
    }
    fn get_function_info(&self) -> &FunctionInfo {
        &self.function_info
    }
    fn get_mut_function_info(&mut self) -> &mut FunctionInfo {
        &mut self.function_info
    }

    pub fn contains_template(&self, template_name: &str) -> bool {
        self.get_template_info().contains_key(template_name)
    }
    fn get_template_info(&self) -> &TemplateInfo {
        &self.template_info
    }
    fn get_mut_template_info(&mut self) -> &mut TemplateInfo {
        &mut self.template_info
    }

    pub fn decompose(self) -> (usize, FunctionInfo, TemplateInfo) {
        (self.fresh_id, self.function_info, self.template_info)
    }
}
