extern crate num_bigint_dig as num_bigint;
extern crate num_traits;
extern crate serde;
extern crate serde_derive;

#[macro_use]
extern crate lalrpop_util;

// Silence clippy warnings for generated code.
lalrpop_mod!(#[allow(clippy::all)] pub lang);

use log::debug;

mod errors;
mod include_logic;
mod parser_logic;
mod syntax_sugar_traits;
mod syntax_sugar_remover;

pub use parser_logic::parse_definition;

use include_logic::FileStack;
use program_structure::ast::{Version, AST};
use program_structure::report::{Report, ReportCollection};
use program_structure::file_definition::{FileID, FileLibrary};
use program_structure::program_archive::ProgramArchive;
use program_structure::template_library::TemplateLibrary;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A result from the Circom parser.
pub enum ParseResult {
    /// The program was successfully parsed without issues.
    Program(Box<ProgramArchive>, ReportCollection),
    /// The parser failed to parse a complete program.
    Library(Box<TemplateLibrary>, ReportCollection),
}

/// 返回这一组文件输入的解析结果
/// 如果是完整的程序（有且只有一个main），返回ProgramArchive
/// 否则序，返回TemplateLibrary
pub fn parse_files(
    file_paths: &[PathBuf],
    libraries: &[PathBuf],
    compiler_version: &Version,
) -> ParseResult {
    let mut reports = ReportCollection::new();                              // 存储警告和错误信息
    let mut file_stack = FileStack::new(file_paths, libraries, &mut reports);   // 管理待处理文件
    let mut file_library = FileLibrary::new();                                 // 存储所有已读取的文件内容
    let mut definitions = HashMap::new();                  // 存储每个文件中定义的 AST 节点
    let mut main_components = Vec::new();                                      // 记录【主组件】信息
    // 遍历解析文件
    while let Some(file_path) = FileStack::take_next(&mut file_stack) {
        match parse_file(&file_path, &mut file_stack, &mut file_library, compiler_version) {
            Ok((file_id, program, mut warnings)) => {
                if let Some(main_component) = program.main_component {
                    main_components.push((file_id, main_component, program.custom_gates)); // 如果这个文件中有main则记录下来
                }
                debug!(
                    "adding {} definitions from `{}`",
                    program.definitions.iter().map(|x| x.name()).collect::<Vec<_>>().join(", "),
                    file_path.display(),
                );
                definitions.insert(file_id, program.definitions);
                reports.append(&mut warnings);
            }
            Err(error) => {
                reports.push(*error);
            }
        }
    }
    // 构建解析结果 
    let mut result = match &main_components[..] { // 根据找到的main决定如何构建最终的ParseResult
        // 成功构建了完整程序（恰好只有一个main）
        [(main_id, main_component, custom_gates)] => {
            // TODO: This calls FillMeta::fill a second time.
            match ProgramArchive::new( // 构建ProgramArchive，这是Circom程序的完整表示（一组指定文件的所有template、function）
                file_library,
                *main_id, // 出现了main的file_id
                main_component,
                &definitions,
                *custom_gates,
            ) {
                Ok(program_archive) => ParseResult::Program(Box::new(program_archive), reports),                   // 成功构建了ProgramArchive，将其包装为ParseResult::Program
                Err((file_library, mut errors)) => {
                    reports.append(&mut errors);
                    let template_library = TemplateLibrary::new(definitions, file_library);     // 创建失败，退而取其次构建为TemplateLibrary，包装为ParseResult::Library
                    ParseResult::Library(Box::new(template_library), reports)
                }
            }
        }
        // 没有主组件main
        [] => {
            // TODO: Maybe use a flag to ensure that a main component must be present.
            let template_library = TemplateLibrary::new(definitions, file_library);             // 没有主组件main，构建为TemplateLibrary，包装为ParseResult::Library
            ParseResult::Library(Box::new(template_library), reports)
        }
        // 多个主组件main，报错
        _ => {
            reports.push(errors::MultipleMainError::produce_report());
            let template_library = TemplateLibrary::new(definitions, file_library);             // 多个主组件main，报告错误，构建为TemplateLibrary，包装为ParseResult::Library
            ParseResult::Library(Box::new(template_library), reports)
        }
    };
    // Remove anonymous components and tuples.
    //
    // TODO: This could be moved to the lifting phase.
    // 移除匿名组件和元组语法糖——对ProgramArchive操作，这是circom程序的完整表示；如果是不是一个完整的程序，视作库(Library)
    match &mut result {
        ParseResult::Program(program_archive, reports) => {
            if program_archive.main_expression().is_anonymous_component() {
                reports.push(
                    errors::AnonymousComponentError::new(
                        Some(program_archive.main_expression().meta()),
                        "The main component cannot contain an anonymous call.",
                        Some("Main component defined here."),
                    )
                    .into_report(),
                );
            }
            let (new_templates, new_functions) = syntax_sugar_remover::remove_syntactic_sugar(
                &program_archive.templates,
                &program_archive.functions,
                &program_archive.file_library,
                reports,
            );
            program_archive.templates = new_templates;
            program_archive.functions = new_functions;
        }
        ParseResult::Library(template_library, reports) => {
            let (new_templates, new_functions) = syntax_sugar_remover::remove_syntactic_sugar(
                &template_library.templates,
                &template_library.functions,
                &template_library.file_library,
                reports,
            );
            template_library.templates = new_templates;
            template_library.functions = new_functions;
        }
    }
    result
}

/// 解析文件的核心
pub fn parse_file(
    file_path: &PathBuf,
    file_stack: &mut FileStack,
    file_library: &mut FileLibrary,                                                                      // 已经读取的文件存储在这个里面，本质是一个HashMap，key是文件路径，value是文件ID
    compiler_version: &Version,
) -> Result<(FileID, AST, ReportCollection), Box<Report>> {
    let mut reports = ReportCollection::new();                                              // 收集解析过程中的所有错误和警告

    debug!("reading file `{}`", file_path.display());
    let (path_str, file_content) = open_file(file_path)?;
    let is_user_input = file_stack.is_user_input(file_path);                                        // 判断文件是否为用户输入文件（而非include）
    let file_id = file_library.add_file(path_str, file_content.clone(), is_user_input);    // 向FileLibrary添加文件，得到唯一的fileID

    debug!("parsing file `{}`", file_path.display());
    let program = parser_logic::parse_file(&file_content, file_id)?;                                // 解析文件内容，得到AST
    match check_compiler_version(file_path, program.compiler_version, compiler_version) {                 // 检查编译器版本是否兼容
        Ok(warnings) => reports.extend(warnings),
        Err(error) => reports.push(*error),
    }
    for include in &program.includes {                                                          // 处理文件中的include语句，遍历AST中所有的include语句，加入待处理队列后续处理
        if let Err(report) = file_stack.add_include(include) {
            reports.push(*report);
        }
    }
    Ok((file_id, program, reports))
}

fn open_file(file_path: &PathBuf) -> Result<(String, String), Box<Report>> /* path, src*/ {
    use errors::FileOsError;
    use std::fs::read_to_string;
    let path_str = format!("{}", file_path.display());
    read_to_string(file_path)
        .map(|contents| (path_str.clone(), contents))
        .map_err(|_| FileOsError { path: path_str.clone() })
        .map_err(|error| Box::new(error.into_report()))
}

fn check_compiler_version(
    file_path: &Path,
    required_version: Option<Version>,
    compiler_version: &Version,
) -> Result<ReportCollection, Box<Report>> {
    use errors::{CompilerVersionError, NoCompilerVersionWarning};
    if let Some(required_version) = required_version {
        if (required_version.0 == compiler_version.0 && required_version.1 < compiler_version.1)
            || (required_version.0 == compiler_version.0
                && required_version.1 == compiler_version.1
                && required_version.2 <= compiler_version.2)
        {
            Ok(vec![])
        } else {
            let error = CompilerVersionError {
                path: format!("{}", file_path.display()),
                required_version,
                version: *compiler_version,
            };
            Err(Box::new(error.into_report()))
        }
    } else {
        let report = NoCompilerVersionWarning::produce_report(NoCompilerVersionWarning {
            path: format!("{}", file_path.display()),
            version: *compiler_version,
        });
        Ok(vec![report])
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::check_compiler_version;

    #[test]
    fn test_compiler_version() {
        let path = PathBuf::from("example.circom");

        assert!(check_compiler_version(&path, None, &(2, 1, 2)).is_ok());
        assert!(check_compiler_version(&path, Some((2, 0, 0)), &(2, 1, 2)).is_ok());
        assert!(check_compiler_version(&path, Some((2, 0, 8)), &(2, 1, 2)).is_ok());
        assert!(check_compiler_version(&path, Some((2, 1, 2)), &(2, 1, 2)).is_ok());

        // We don't support Circom 1.
        assert!(check_compiler_version(&path, Some((1, 0, 0)), &(2, 0, 8)).is_err());
        assert!(check_compiler_version(&path, Some((2, 1, 2)), &(2, 0, 8)).is_err());
        assert!(check_compiler_version(&path, Some((2, 1, 4)), &(2, 1, 2)).is_err());
    }
}
