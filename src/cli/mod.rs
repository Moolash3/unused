use crate::analyzers::run_analysis;
use crate::languages::elixir::ElixirAnalyzer;
use crate::output::{print_results, OutputFormat};
use anyhow::Result;
use clap::{Parser, ValueEnum};
use std::path::PathBuf;

/// Scan a directory for unused function definitions across supported languages
#[derive(Parser, Debug)]
#[command(
    name = "cleancode",
    about = "Detects unused function definitions in your source code",
    version,
    long_about = None
)]
pub struct Cli {
    /// Directory to scan (defaults to current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Language to analyze (auto-detected if not specified)
    #[arg(short, long, value_enum)]
    pub language: Option<LanguageArg>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "pretty")]
    pub format: OutputFormatArg,

    /// Include private/underscore-prefixed functions in the report
    #[arg(long, default_value_t = false)]
    pub include_private: bool,

    /// Suppress all output except results
    #[arg(short, long, default_value_t = false)]
    pub quiet: bool,

    /// Exit with non-zero code if unused functions are found
    #[arg(long, default_value_t = false)]
    pub fail_on_unused: bool,

    /// Path to the dependencies directory (e.g. `deps/` in a Mix project).
    /// When provided, dep source files are scanned for `defoverridable`
    /// declarations so that macro-injected callback overrides are not
    /// reported as unused.
    #[arg(long, value_name = "PATH")]
    pub deps: Option<PathBuf>,

    /// Suppress similar-call hints (same name, different arity) in the output
    #[arg(long, default_value_t = false)]
    pub no_hints: bool,

    /// Module names to exclude from the unused function report.
    /// Accepts dotted Elixir module names. Can be specified as repeated flags
    /// or as a comma-separated list (or both):
    ///   --exclude Authorization.Permission --exclude MyApp.Roles
    ///   --exclude Authorization.Permission,MyApp.Roles
    #[arg(long = "exclude", value_name = "MODULE[,MODULE...]", action = clap::ArgAction::Append)]
    pub exclude_modules: Vec<String>,

    /// Directory paths to exclude from scanning entirely.
    /// Any file whose path contains the given string is skipped.
    /// Can be specified multiple times or as a comma-separated list:
    ///   --exclude-dir test/factories --exclude-dir test/support
    ///   --exclude-dir test/factories,test/support
    #[arg(long = "exclude-dir", value_name = "PATH[,PATH...]", action = clap::ArgAction::Append)]
    pub exclude_dirs: Vec<String>,

    /// Print the dep_callbacks table to stderr after scanning deps and exit.
    /// Use this to diagnose why a function is still being flagged as unused
    /// even though it should be covered by a dependency's defoverridable.
    #[arg(long, default_value_t = false)]
    pub debug_deps: bool,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum LanguageArg {
    Elixir,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormatArg {
    Pretty,
    Json,
    Summary,
}

impl From<OutputFormatArg> for OutputFormat {
    fn from(arg: OutputFormatArg) -> Self {
        match arg {
            OutputFormatArg::Pretty => OutputFormat::Pretty,
            OutputFormatArg::Json => OutputFormat::Json,
            OutputFormatArg::Summary => OutputFormat::Summary,
        }
    }
}

impl Cli {
    pub fn run(self) -> Result<()> {
        let path = self.path.canonicalize().unwrap_or(self.path.clone());

        // Resolve the deps path if provided, otherwise try the conventional
        // `deps/` subdirectory of the scan root (standard Mix project layout).
        let deps_path = self
            .deps
            .map(|p| p.canonicalize().unwrap_or(p))
            .or_else(|| {
                let conventional = path.join("deps");
                if conventional.is_dir() {
                    Some(conventional)
                } else {
                    None
                }
            });

        if !self.quiet {
            eprintln!("🔍 Scanning: {}", path.display());
            if let Some(ref d) = deps_path {
                eprintln!("📦 Using deps: {}", d.display());
            }
        }

        // --debug-deps: build the analyzer, dump what was found, then exit.
        // This lets the user verify that their dependency's defoverridable
        // callbacks were detected before running a full analysis.
        if self.debug_deps {
            let elixir = match deps_path.as_deref() {
                Some(p) => {
                    ElixirAnalyzer::debug_scan_deps(p);
                    ElixirAnalyzer::new().with_deps(p)
                }
                None => ElixirAnalyzer::new(),
            };
            elixir.dump_dep_callbacks();
            return Ok(());
        }

        // Flatten comma-separated values: `--exclude "A,B"` and `--exclude A --exclude B`
        // both produce the same list.
        let exclude_modules: Vec<String> = self
            .exclude_modules
            .iter()
            .flat_map(|s| s.split(','))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if !self.quiet && !exclude_modules.is_empty() {
            eprintln!("🚫 Excluding modules: {}", exclude_modules.join(", "));
        }

        // Flatten comma-separated dir values the same way as modules.
        let exclude_dirs: Vec<String> = self
            .exclude_dirs
            .iter()
            .flat_map(|s| s.split(','))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if !self.quiet && !exclude_dirs.is_empty() {
            eprintln!("🚫 Excluding dirs: {}", exclude_dirs.join(", "));
        }

        let results = run_analysis(
            &path,
            self.language.as_ref(),
            self.include_private,
            deps_path.as_deref(),
            &exclude_modules,
            &exclude_dirs,
        )?;

        let unused_count = results
            .iter()
            .map(|r| r.unused_functions.len())
            .sum::<usize>();

        print_results(&results, self.format.into(), !self.no_hints)?;

        if self.fail_on_unused && unused_count > 0 {
            std::process::exit(1);
        }

        Ok(())
    }
}
