use anyhow::Result;
use rayon::prelude::*;
use std::collections::HashSet;

use std::path::Path;
use walkdir::WalkDir;

use crate::cli::LanguageArg;
use crate::languages::{
    elixir::ElixirAnalyzer, FileAnalysis, FunctionCall, FunctionDef, LanguageAnalyzer,
};

/// Result of the complete cross-file analysis for one language
#[derive(Debug)]
pub struct AnalysisResult {
    pub language: String,
    pub files_scanned: usize,
    pub unused_functions: Vec<UnusedFunction>,
    pub total_definitions: usize,
}

/// A function that was defined but never called
#[derive(Debug)]
pub struct UnusedFunction {
    pub def: FunctionDef,
    /// Call sites that share the same name but a different arity — hints at a likely typo or refactor
    pub similar_calls: Vec<FunctionCall>,
}

/// Return all built-in analyzers, initialised with an optional deps path for
/// dep-scanning (e.g. to resolve `defoverridable` callbacks in Elixir).
pub fn all_analyzers(deps_path: Option<&Path>) -> Vec<Box<dyn LanguageAnalyzer>> {
    let elixir: Box<dyn LanguageAnalyzer> = match deps_path {
        Some(p) => Box::new(ElixirAnalyzer::new().with_deps(p)),
        None => Box::new(ElixirAnalyzer::new()),
    };

    vec![
        elixir,
        // Future: Box::new(RubyAnalyzer::new()),
        // Future: Box::new(PythonAnalyzer::new()),
    ]
}

/// Run the full analysis pipeline:
/// 1. Discover all relevant source files
/// 2. Parse every file in parallel
/// 3. Build a global call-site index
/// 4. Identify definitions that are never referenced
pub fn run_analysis(
    root: &Path,
    language_filter: Option<&LanguageArg>,
    include_private: bool,
    deps_path: Option<&Path>,
    exclude_modules: &[String],
    exclude_dirs: &[String],
) -> Result<Vec<AnalysisResult>> {
    let analyzers = all_analyzers(deps_path);

    // Filter analyzers based on the user's --language flag
    let active: Vec<&Box<dyn LanguageAnalyzer>> = analyzers
        .iter()
        .filter(|a| match language_filter {
            Some(LanguageArg::Elixir) => a.name() == "Elixir",
            None => true,
        })
        .collect();

    let mut results = Vec::new();

    for analyzer in active {
        let files = collect_files(root, analyzer.as_ref(), exclude_dirs);

        if files.is_empty() {
            continue;
        }

        // Parse all files in parallel
        let analyses: Vec<FileAnalysis> = files
            .par_iter()
            .filter_map(|path| analyzer.analyze_file(path).ok())
            .collect();

        let result = cross_reference(analyzer.name(), analyses, include_private, exclude_modules);
        results.push(result);
    }

    Ok(results)
}

/// Walk the directory tree and collect files supported by the given analyzer.
/// The `deps` directory is intentionally excluded here — it is scanned
/// separately by `ElixirAnalyzer::with_deps` for `defoverridable` metadata,
/// but its source files should never appear in the unused-function report.
fn collect_files(
    root: &Path,
    analyzer: &dyn LanguageAnalyzer,
    exclude_dirs: &[String],
) -> Vec<std::path::PathBuf> {
    WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .filter(|p| {
            // Skip built-in ignored directories.
            if p.components().any(|c| {
                let s = c.as_os_str().to_string_lossy();
                s.starts_with('.') || s == "_build" || s == "deps" || s == "node_modules"
            }) {
                return false;
            }
            // Skip user-specified excluded directories.
            // Normalise separators so `test/factories` matches on all platforms.
            if !exclude_dirs.is_empty() {
                let normalised = p.to_string_lossy().replace('\\', "/");
                if exclude_dirs
                    .iter()
                    .any(|dir| normalised.contains(dir.as_str()))
                {
                    return false;
                }
            }
            true
        })
        .filter(|p| analyzer.supports_file(p))
        .collect()
}

/// Given all parsed file analyses for one language, produce a cross-referenced report.
fn cross_reference(
    language: &str,
    analyses: Vec<FileAnalysis>,
    include_private: bool,
    exclude_modules: &[String],
) -> AnalysisResult {
    let files_scanned = analyses.len();

    // Build a set of file paths whose declared modules are in the exclude list.
    // We read each file and check its `defmodule` declarations rather than
    // inferring module names from paths — the two don't always correspond.
    let defmodule_re =
        regex::Regex::new(r"(?m)^\s*defmodule\s+((?:[A-Z][a-zA-Z0-9_]*\.)*[A-Z][a-zA-Z0-9_]*)")
            .unwrap();

    let excluded_files: HashSet<String> = if exclude_modules.is_empty() {
        HashSet::new()
    } else {
        // Collect the unique set of files from all analyses, then check each one.
        analyses
            .iter()
            .flat_map(|fa| fa.definitions.iter().map(|d| d.file.clone()))
            .collect::<HashSet<_>>()
            .into_iter()
            .filter(|file| {
                let source = match std::fs::read_to_string(file) {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                defmodule_re.captures_iter(&source).any(|cap| {
                    let declared = cap.get(1).unwrap().as_str();
                    exclude_modules.iter().any(|ex| ex == declared)
                })
            })
            .collect()
    };

    // Collect all calls upfront so we can do two things:
    // 1. Build the exact-match key set for unused detection
    // 2. Find same-name-different-arity calls as hints on each unused function
    let all_calls: Vec<FunctionCall> = analyses
        .iter()
        .flat_map(|fa| fa.calls.iter().cloned())
        .collect();

    // A call with arity None (e.g. from `apply(mod, :fn, args_variable)`) matches
    // any definition of that name regardless of arity.
    let wildcard_called_names: HashSet<String> = all_calls
        .iter()
        .filter(|c| c.arity.is_none())
        .map(|c| c.name.clone())
        .collect();

    let called_keys: HashSet<String> = all_calls
        .iter()
        .filter_map(|c| c.arity.map(|_| c.canonical_key()))
        .collect();

    // Collect every definition; deduplicate by (file, line) to handle overlapping regexes.
    // Skip definitions whose file was identified as belonging to an excluded module.
    let mut seen: HashSet<(String, usize)> = HashSet::new();
    let all_defs: Vec<&FunctionDef> = analyses
        .iter()
        .flat_map(|fa| fa.definitions.iter())
        .filter(|d| {
            if !include_private && d.is_private {
                return false;
            }
            if excluded_files.contains(&d.file) {
                return false;
            }
            seen.insert((d.file.clone(), d.line))
        })
        .collect();

    let total_definitions = all_defs.len();

    // A definition is "unused" when:
    //   - its exact name/arity key appears in no call site, AND
    //   - its name does not appear in any wildcard (arity-unknown) call
    let unused_functions: Vec<UnusedFunction> = all_defs
        .into_iter()
        .filter(|d| {
            !called_keys.contains(&d.canonical_key()) && !wildcard_called_names.contains(&d.name)
        })
        .map(|d| {
            let similar_calls = all_calls
                .iter()
                .filter(|c| c.name == d.name && c.arity != d.arity)
                .cloned()
                .collect();
            UnusedFunction {
                def: d.clone(),
                similar_calls,
            }
        })
        .collect();

    AnalysisResult {
        language: language.to_string(),
        files_scanned,
        unused_functions,
        total_definitions,
    }
}
