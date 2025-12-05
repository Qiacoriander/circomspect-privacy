use super::errors::{ParsingError, UnclosedCommentError};
use super::lang;

use program_structure::ast::AST;
use program_structure::report::Report;
use program_structure::file_definition::FileID;

/// 对circom文件进行预处理，主要是处理注释，以便parser正常解析
/// 同时保留原来位置，方便定位
pub fn preprocess(expr: &str, file_id: FileID) -> Result<String, Box<Report>> {
    let mut pp = String::new();
    let mut state = 0;
    let mut loc = 0;
    let mut block_start = 0;

    let mut it = expr.chars();
    while let Some(c0) = it.next() {
        loc += 1;
        match (state, c0) {
            (0, '/') => {
                loc += 1;
                match it.next() {
                    Some('/') => {
                        state = 1;
                        pp.push(' ');
                        pp.push(' ');
                    }
                    Some('*') => {
                        block_start = loc;
                        state = 2;
                        pp.push(' ');
                        pp.push(' ');
                    }
                    Some(c1) => {
                        pp.push(c0);
                        pp.push(c1);
                    }
                    None => {
                        pp.push(c0);
                        break;
                    }
                }
            }
            (0, _) => pp.push(c0),
            (1, '\n') => {
                pp.push(c0);
                state = 0;
            }
            (2, '*') => {
                loc += 1;
                match it.next() {
                    Some('/') => {
                        pp.push(' ');
                        pp.push(' ');
                        state = 0;
                    }
                    Some(c) => {
                        pp.push(' ');
                        for _i in 0..c.len_utf8() {
                            pp.push(' ');
                        }
                    }
                    None => {
                        let error =
                            UnclosedCommentError { location: block_start..block_start, file_id };
                        return Err(Box::new(error.into_report()));
                    }
                }
            }
            (_, c) => {
                for _i in 0..c.len_utf8() {
                    pp.push(' ');
                }
            }
        }
    }
    Ok(pp)
}

pub fn parse_file(src: &str, file_id: FileID) -> Result<AST, Box<Report>> {
    use lalrpop_util::ParseError::*;
    lang::ParseAstParser::new()
        .parse(&preprocess(src, file_id)?)    // 解析获得AST
        .map(|mut ast| {                                                // 增强调试能力，给所有#include引入的文件设置当前文件ID，方便报错时精确指出是哪个include出现的问题
            // Set file ID for better error reporting.
            for include in &mut ast.includes {
                include.meta.set_file_id(file_id);
            }
            ast
        })
        .map_err(|parse_error| match parse_error {              // 错误转换，将LALRPOP解析错误转换为自定义错误
            InvalidToken { location } => ParsingError {
                file_id,
                message: "Invalid token found.".to_string(),
                location: location..location,
            },
            UnrecognizedToken { ref token, ref expected } => ParsingError {
                file_id,
                message: format!(
                    "Unrecognized token `{}` found.{}",
                    token.1,
                    format_expected(expected)
                ),
                location: token.0..token.2,
            },
            ExtraToken { ref token } => ParsingError {
                file_id,
                message: format!("Extra token `{}` found.", token.2),
                location: token.0..token.2,
            },
            _ => ParsingError { file_id, message: format!("{parse_error}"), location: 0..0 },
        })
        .map_err(|error| Box::new(error.into_report()))
}

pub fn parse_string(src: &str) -> Option<AST> {
    let src = preprocess(src, 0).ok()?;
    lang::ParseAstParser::new().parse(&src).ok()
}

/// Parse a single (function or template) definition for testing purposes.
use program_structure::ast::Definition;

pub fn parse_definition(src: &str) -> Option<Definition> {
    match parse_string(src) {
        Some(AST { mut definitions, .. }) if definitions.len() == 1 => definitions.pop(),
        _ => None,
    }
}

#[must_use]
fn format_expected(tokens: &[String]) -> String {
    if tokens.is_empty() {
        String::new()
    } else {
        let tokens = tokens
            .iter()
            .enumerate()
            .map(|(index, token)| {
                if index == 0 {
                    token.replace('\"', "`")
                } else if index < tokens.len() - 1 {
                    format!(", {}", token.replace('\"', "`"))
                } else {
                    format!(" or {}", token.replace('\"', "`"))
                }
            })
            .collect::<Vec<_>>()
            .join("");
        format!(" Expected one of {tokens}.")
    }
}

#[cfg(test)]
mod tests {
    use super::parse_string;
    use crate::parse_definition;
    use program_structure::ast::{Definition, Statement, VariableType, SignalType};
    use program_structure::cfg::IntoCfg;
    use program_structure::constants::Curve;
    use program_structure::report::ReportCollection;

    #[test]
    fn test_parse_string() {
        let function = r#"
            function f(m) {
                // This is a comment.
                var x = 1024;
                var y = 16;
                while (x < m) {
                    x += y;
                }
                if (x == m) {
                    x = 0;
                }
                /* This is another comment. */
                return x;
            }
        "#;
        let _ = parse_string(function);

        let template = r#"
            template T(m) {
                signal input in[m];
                signal output out;

                var sum = 0;
                for (var i = 0; i < m; i++) {
                    sum += in[i];
                }
                out <== sum;
            }
        "#;
        let _ = parse_string(template);
    }

    #[test]
    fn test_parse_private_signal_ast() {
        let src = r#"
            template T() {
                signal private input a;
                signal input b;
                signal output c;
            }
        "#;
        let def = parse_definition(src).expect("definition parsed");
        match def {
            Definition::Template { body, .. } => {
                match body {
                    Statement::Block { stmts, .. } => {
                        let mut has_a = false;
                        let mut has_b = false;
                        let mut has_c = false;
                        for stmt in stmts {
                            if let Statement::InitializationBlock { xtype, initializations, .. } = stmt {
                                match xtype {
                                    VariableType::Signal(SignalType::Input, _, true) => {
                                        has_a = initializations.iter().any(|s| match s {
                                            Statement::Declaration { name, .. } => name == "a",
                                            _ => false,
                                        });
                                    }
                                    VariableType::Signal(SignalType::Input, _, false) => {
                                        has_b = initializations.iter().any(|s| match s {
                                            Statement::Declaration { name, .. } => name == "b",
                                            _ => false,
                                        });
                                    }
                                    VariableType::Signal(SignalType::Output, _, false) => {
                                        has_c = initializations.iter().any(|s| match s {
                                            Statement::Declaration { name, .. } => name == "c",
                                            _ => false,
                                        });
                                    }
                                    _ => {}
                                }
                            }
                        }
                        assert!(has_a && has_b && has_c);
                    }
                    _ => panic!("expected block body"),
                }
            }
            _ => panic!("expected template definition"),
        }
    }

    #[test]
    fn test_cfg_private_public_iterators() {
        let src = r#"
            template T() {
                signal private input a;
                signal input b;
                signal output c;
            }
        "#;
        let def = parse_definition(src).expect("definition parsed");
        let mut reports = ReportCollection::new();
        let cfg = def
            .into_cfg(&Curve::default(), &mut reports)
            .expect("cfg built");

        let priv_inputs: Vec<String> = cfg.private_input_signals().map(|n| n.to_string()).collect();
        let pub_inputs: Vec<String> = cfg.public_input_signals().map(|n| n.to_string()).collect();
        let all_inputs: Vec<String> = cfg.input_signals().map(|n| n.to_string()).collect();

        assert_eq!(priv_inputs, vec!["a"]);
        assert_eq!(pub_inputs, vec!["b"]);
        assert_eq!(all_inputs.len(), 2);
        assert!(all_inputs.contains(&"a".to_string()));
        assert!(all_inputs.contains(&"b".to_string()));
    }
}
