pub mod elixir;

use anyhow::Result;
use std::path::Path;

/// A detected function definition with location information
#[derive(Debug, Clone)]
pub struct FunctionDef {
    /// The function name (without arity for Elixir)
    pub name: String,
    /// Arity (number of arguments) — Some for Elixir, None for languages without arity
    pub arity: Option<usize>,
    /// 1-based line number where the function is defined
    pub line: usize,
    /// Source file path
    pub file: String,
    /// Whether this function is private (e.g. `defp` in Elixir)
    pub is_private: bool,
}

impl FunctionDef {
    /// Returns a canonical key used to match calls to definitions.
    /// For Elixir: "name/arity". For others: "name".
    pub fn canonical_key(&self) -> String {
        match self.arity {
            Some(a) => format!("{}/{}", self.name, a),
            None => self.name.clone(),
        }
    }
}

/// A detected function call site
#[derive(Debug, Clone)]
pub struct FunctionCall {
    /// The function name as it appears at the call site
    pub name: String,
    /// Arity at the call site (if known)
    pub arity: Option<usize>,
    /// 1-based line number
    pub line: usize,
    /// Source file path
    pub file: String,
}

impl FunctionCall {
    pub fn canonical_key(&self) -> String {
        match self.arity {
            Some(a) => format!("{}/{}", self.name, a),
            None => self.name.clone(),
        }
    }
}

/// The result of analyzing a single source file
#[derive(Debug)]
pub struct FileAnalysis {
    pub definitions: Vec<FunctionDef>,
    pub calls: Vec<FunctionCall>,
}

/// Trait that every language analyzer must implement.
/// Add a new language by implementing this trait and registering it
/// in `analyzers::all_analyzers()`.
pub trait LanguageAnalyzer: Send + Sync {
    /// Human-readable name of the language (e.g. "Elixir")
    fn name(&self) -> &'static str;

    /// File extensions this analyzer handles (without leading dot)
    fn extensions(&self) -> &[&'static str];

    /// Returns true if this analyzer can handle the given file
    fn supports_file(&self, path: &Path) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .map(|ext| self.extensions().contains(&ext))
            .unwrap_or(false)
    }

    /// Parse a single source file and return all definitions and call sites found
    fn analyze_file(&self, path: &Path) -> Result<FileAnalysis>;
}
