use anyhow::Result;
use colored::Colorize;
use serde::Serialize;

use crate::analyzers::{AnalysisResult, UnusedFunction};

pub enum OutputFormat {
    Pretty,
    Json,
    Summary,
}

#[derive(Serialize)]
struct JsonOutput<'a> {
    language: &'a str,
    files_scanned: usize,
    total_definitions: usize,
    unused_count: usize,
    unused_functions: Vec<JsonFunction<'a>>,
}

#[derive(Serialize)]
struct JsonFunction<'a> {
    name: &'a str,
    arity: Option<usize>,
    file: &'a str,
    line: usize,
    is_private: bool,
    similar_calls: Vec<JsonCall<'a>>,
}

#[derive(Serialize)]
struct JsonCall<'a> {
    name: &'a str,
    arity: Option<usize>,
    file: &'a str,
    line: usize,
}

pub fn print_results(
    results: &[AnalysisResult],
    format: OutputFormat,
    show_hints: bool,
) -> Result<()> {
    match format {
        OutputFormat::Pretty => print_pretty(results, show_hints),
        OutputFormat::Json => print_json(results, show_hints),
        OutputFormat::Summary => print_summary(results),
    }
}

fn print_pretty(results: &[AnalysisResult], show_hints: bool) -> Result<()> {
    if results.is_empty() {
        println!("{}", "No supported source files found.".yellow());
        return Ok(());
    }

    for result in results {
        println!(
            "\n{} {} — {} file{} scanned, {} definition{} total",
            "▶".cyan().bold(),
            result.language.bold(),
            result.files_scanned,
            if result.files_scanned == 1 { "" } else { "s" },
            result.total_definitions,
            if result.total_definitions == 1 {
                ""
            } else {
                "s"
            },
        );

        if result.unused_functions.is_empty() {
            println!("  {} No unused functions found!", "✓".green().bold());
            continue;
        }

        println!(
            "  {} {} unused function{} found:\n",
            "✗".red().bold(),
            result.unused_functions.len(),
            if result.unused_functions.len() == 1 {
                ""
            } else {
                "s"
            },
        );

        // Group by file for readability
        let mut by_file: std::collections::BTreeMap<&str, Vec<&UnusedFunction>> =
            std::collections::BTreeMap::new();

        for uf in &result.unused_functions {
            by_file.entry(&uf.def.file).or_default().push(uf);
        }

        for (file, fns) in by_file {
            println!("  {}", file.dimmed());
            for uf in fns {
                let visibility = if uf.def.is_private {
                    "private".dimmed().to_string()
                } else {
                    "public".to_string()
                };

                let signature = match uf.def.arity {
                    Some(a) => format!("{}/{}", uf.def.name, a),
                    None => uf.def.name.clone(),
                };

                println!(
                    "    {} {} {}",
                    format!("line {:>4}", uf.def.line).dimmed(),
                    signature.yellow().bold(),
                    format!("({})", visibility).dimmed(),
                );

                // Surface same-name-different-arity calls as refactor hints
                if show_hints {
                    for call in &uf.similar_calls {
                        let call_sig = match call.arity {
                            Some(a) => format!("{}/{}", call.name, a),
                            None => call.name.clone(),
                        };
                        println!(
                            "      {} called as {} at {}:{}",
                            "~".yellow(),
                            call_sig.yellow(),
                            call.file.dimmed(),
                            call.line,
                        );
                    }
                }
            }
            println!();
        }
    }

    // --- Summary footer ---
    let total_files: usize = results.iter().map(|r| r.files_scanned).sum();
    let total_defs: usize = results.iter().map(|r| r.total_definitions).sum();
    let total_unused: usize = results.iter().map(|r| r.unused_functions.len()).sum();

    println!("{}", "─".repeat(50).dimmed());
    println!(
        "{} {} file{}, {} definition{}, {} unused",
        "Summary:".bold(),
        total_files,
        if total_files == 1 { "" } else { "s" },
        total_defs,
        if total_defs == 1 { "" } else { "s" },
        if total_unused == 0 {
            total_unused.to_string().green().bold().to_string()
        } else {
            total_unused.to_string().red().bold().to_string()
        },
    );

    Ok(())
}

fn print_json(results: &[AnalysisResult], show_hints: bool) -> Result<()> {
    let json_results: Vec<JsonOutput> = results
        .iter()
        .map(|r| JsonOutput {
            language: &r.language,
            files_scanned: r.files_scanned,
            total_definitions: r.total_definitions,
            unused_count: r.unused_functions.len(),
            unused_functions: r
                .unused_functions
                .iter()
                .map(|uf| JsonFunction {
                    name: &uf.def.name,
                    arity: uf.def.arity,
                    file: &uf.def.file,
                    line: uf.def.line,
                    is_private: uf.def.is_private,
                    similar_calls: if show_hints {
                        uf.similar_calls
                            .iter()
                            .map(|c| JsonCall {
                                name: &c.name,
                                arity: c.arity,
                                file: &c.file,
                                line: c.line,
                            })
                            .collect()
                    } else {
                        vec![]
                    },
                })
                .collect(),
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&json_results)?);
    Ok(())
}

fn print_summary(results: &[AnalysisResult]) -> Result<()> {
    let total_unused: usize = results.iter().map(|r| r.unused_functions.len()).sum();
    let total_defs: usize = results.iter().map(|r| r.total_definitions).sum();
    let total_files: usize = results.iter().map(|r| r.files_scanned).sum();

    println!(
        "Scanned {} file(s) | {} definition(s) | {} unused",
        total_files, total_defs, total_unused
    );

    for r in results {
        if !r.unused_functions.is_empty() {
            println!("\n[{}] {} unused:", r.language, r.unused_functions.len());
            for uf in &r.unused_functions {
                let sig = match uf.def.arity {
                    Some(a) => format!("{}/{}", uf.def.name, a),
                    None => uf.def.name.clone(),
                };
                println!("  {}  {}:{}", sig, uf.def.file, uf.def.line);
            }
        }
    }

    Ok(())
}
