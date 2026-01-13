use std::collections::HashSet;
use std::path::PathBuf;
use std::process::ExitCode;
use clap::{CommandFactory, Parser};

use program_analysis::config;
use program_analysis::analysis_runner::AnalysisRunner;
use program_analysis::privacy_taint::LeakSeverity;
use std::str::FromStr;

use program_structure::constants::Curve;
use program_structure::file_definition::FileID;
use program_structure::report::Report;
use program_structure::report::MessageCategory;
use program_structure::writers::{LogWriter, ReportWriter, SarifWriter, CachedStdoutWriter};

#[derive(Parser, Debug)]
#[command(styles=cli_styles())]
/// A static analyzer and linter for Circom programs.
struct Cli {
    /// Initial input file(s)
    #[clap(name = "INPUT")]
    input_files: Vec<PathBuf>,

    /// Library file paths
    #[clap(short = 'L', long = "library", name = "LIBRARIES")]
    libraries: Vec<PathBuf>,

    /// Output level (INFO, WARNING, or ERROR)
    #[clap(short = 'l', long = "level", name = "LEVEL", default_value = config::DEFAULT_LEVEL)]
    output_level: MessageCategory,

    /// Output analysis results to a Sarif file
    #[clap(short, long, name = "OUTPUT")]
    sarif_file: Option<PathBuf>,

    /// Ignore results from given analysis passes
    #[clap(short = 'a', long = "allow", name = "ID")]
    allow_list: Vec<String>,

    /// Enable verbose output
    #[clap(short = 'v', long = "verbose")]
    verbose: bool,

    /// Set curve (BN254, BLS12_381, or GOLDILOCKS)
    #[clap(short = 'c', long = "curve", name = "NAME", default_value = config::DEFAULT_CURVE)]
    curve: Curve,

    /// Analysis mode: 'all' analyzes all templates/functions (all inputs are private),
    /// 'main' starts from main component and respects public input declarations
    #[clap(short = 'm', long = "mode", name = "MODE", default_value = "all")]
    analysis_mode: String,

    /// Leakage threshold in bits for quantified analysis (CS0021)
    #[clap(long = "leak-threshold", name = "BITS", default_value = "8")]
    leak_threshold: usize,

    /// Minimum leakage severity to trigger a WARNING (others will be INFO)
    #[clap(long = "min-leak-severity", name = "SEVERITY", default_value = config::DEFAULT_MIN_LEAK_SEVERITY)]
    min_leak_severity: String,
}

/// Styles the help output for the [`Cli`].
fn cli_styles() -> clap::builder::Styles {
    use clap::builder::styling::*;

    Styles::styled()
        .header(AnsiColor::Yellow.on_default())
        .usage(AnsiColor::Green.on_default())
        .literal(AnsiColor::Green.on_default())
        .placeholder(AnsiColor::Green.on_default())
}

/// Returns true if a primary location of the report corresponds to a file
/// specified on the command line by the user.
fn filter_by_file(report: &Report, user_inputs: &HashSet<FileID>) -> bool {
    report.primary_file_ids().iter().any(|file_id| user_inputs.contains(file_id))
}

/// Returns true if the report level is greater than or equal to the given
/// level.
fn filter_by_level(report: &Report, output_level: &MessageCategory) -> bool {
    report.category() >= output_level
}

/// Returns true if the report ID is not in the given list.
fn filter_by_id(report: &Report, allow_list: &[String]) -> bool {
    !allow_list.contains(&report.id())
}

fn main() -> ExitCode {
    // Initialize logger and options.
    pretty_env_logger::init();
    let options = Cli::parse();
    if options.input_files.is_empty() {
        match Cli::command().print_help() {
            Ok(()) => return ExitCode::SUCCESS,
            Err(_) => return ExitCode::FAILURE,
        }
    }

    // 验证分析模式参数
    let analysis_mode = options.analysis_mode.to_lowercase();
    if analysis_mode != "all" && analysis_mode != "main" {
        eprintln!(
            "Error: Invalid analysis mode '{}'. Must be 'all' or 'main'.",
            options.analysis_mode
        );
        return ExitCode::FAILURE;
    }

    let min_leak_severity = match LeakSeverity::from_str(&options.min_leak_severity) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // Set up analysis runner.
    // 解析阶段
    let (mut runner, reports) = AnalysisRunner::new(options.curve)
        .with_libraries(&options.libraries)
        .with_leak_threshold(options.leak_threshold)
        .with_min_leak_severity(min_leak_severity)
        .with_files(&options.input_files); // 传入后，会调用parser执行解析

    // Set up writer and write reports to `stdout`.
    let allow_list = options.allow_list.clone();
    let user_inputs = runner.file_library().user_inputs().clone();
    let mut stdout_writer = CachedStdoutWriter::new(options.verbose)
        .add_filter(move |report: &Report| filter_by_level(report, &options.output_level))
        .add_filter(move |report: &Report| filter_by_file(report, &user_inputs))
        .add_filter(move |report: &Report| filter_by_id(report, &allow_list));
    stdout_writer.write_reports(&reports, runner.file_library());

    // Analyze functions and templates in user provided input files.
    // 改用 CfgManager 流程以支持递归分析

    // 1. 生成所有 CFG
    runner.generate_all_cfgs();

    // 2. 链接所有引用 (这会清空 runner 中的 CFG，移入 cfg_manager)
    let cfg_manager = runner.link_all_cfg_references();

    // 3. 运行分析
    if analysis_mode == "main" {
        // 模式 2：从 main 开始递归分析
        if let Some(main_info) = runner.main_component() {
            if let Some(cfg_ref) = cfg_manager.get_template_cfg_ref(&main_info.template_name) {
                let cfg = cfg_ref.borrow();
                stdout_writer.write_message(&format!(
                    "从 main component '{}' 开始分析，公开输入：{:?}",
                    main_info.template_name, main_info.public_inputs
                ));

                // 运行隐私污点分析
                let mut reports =
                    program_analysis::privacy_taint::find_privacy_taint_leaks_for_main(
                        &cfg,
                        &main_info.public_inputs,
                        options.leak_threshold,
                        min_leak_severity,
                    );

                // 运行其他分析 (如果有)
                // 注意：这里手动调用其他 pass，因为 get_analysis_passes 需要 Context
                reports.append(&mut program_analysis::bitwise_complement::find_bitwise_complement(
                    &cfg,
                ));
                reports.append(&mut program_analysis::signal_assignments::find_signal_assignments(
                    &cfg,
                ));

                stdout_writer.write_reports(&reports, runner.file_library());
            } else {
                eprintln!(
                    "Error: Main component template '{}' not found in CFG.",
                    main_info.template_name
                );
            }
        } else {
            stdout_writer.write_message(
                "错误：没有找到 main component。请确保输入文件包含一个 main component声明。",
            );
            stdout_writer.write_message("如果你想分析库组件，请使用 --mode all 模式。");
        }
    } else {
        // 模式 1：分析所有模板
        // 先分析函数
        for name in cfg_manager.function_names() {
            if let Some(cfg_ref) = cfg_manager.get_function_cfg_ref(name) {
                let cfg = cfg_ref.borrow();
                stdout_writer.write_message(&format!("analyzing function '{name}'"));
                // 函数通常只做基础检查，不做隐私分析（因为没有隐私输入定义）
                let mut reports =
                    program_analysis::bitwise_complement::find_bitwise_complement(&cfg);
                reports.append(&mut program_analysis::signal_assignments::find_signal_assignments(
                    &cfg,
                ));
                stdout_writer.write_reports(&reports, runner.file_library());
            }
        }

        // 再分析模板
        for name in cfg_manager.template_names() {
            if let Some(cfg_ref) = cfg_manager.get_template_cfg_ref(name) {
                let cfg = cfg_ref.borrow();
                stdout_writer.write_message(&format!("analyzing template '{name}'"));

                // 运行隐私分析
                let mut reports = program_analysis::privacy_taint::find_privacy_taint_leaks(
                    &cfg,
                    Some(&runner),
                    options.leak_threshold,
                    min_leak_severity,
                );

                // 运行其他分析
                reports.append(&mut program_analysis::bitwise_complement::find_bitwise_complement(
                    &cfg,
                ));
                reports.append(&mut program_analysis::signal_assignments::find_signal_assignments(
                    &cfg,
                ));

                stdout_writer.write_reports(&reports, runner.file_library());
            }
        }
    }

    // If a Sarif file is passed to the program we write the reports to it.
    if let Some(sarif_file) = options.sarif_file {
        let allow_list = options.allow_list.clone();
        let user_inputs = runner.file_library().user_inputs().clone();
        let mut sarif_writer = SarifWriter::new(&sarif_file)
            .add_filter(move |report: &Report| filter_by_level(report, &options.output_level))
            .add_filter(move |report: &Report| filter_by_file(report, &user_inputs))
            .add_filter(move |report: &Report| filter_by_id(report, &allow_list));
        if sarif_writer.write_reports(stdout_writer.reports(), runner.file_library()) > 0 {
            stdout_writer.write_message(&format!("Result written to `{}`.", sarif_file.display()));
        }
    }

    // Use the exit code to indicate if any issues were found.
    match stdout_writer.reports_written() {
        0 => {
            stdout_writer.write_message("No issues found.");
            ExitCode::SUCCESS
        }
        1 => {
            stdout_writer.write_message("1 issue found.");
            ExitCode::FAILURE
        }
        n => {
            stdout_writer.write_message(&format!("{n} issues found."));
            ExitCode::FAILURE
        }
    }
}
