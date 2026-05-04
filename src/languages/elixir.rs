use anyhow::{Context, Result};
use regex::Regex;
use std::path::Path;

use super::{FileAnalysis, FunctionCall, FunctionDef, LanguageAnalyzer};

/// Analyzer for Elixir source files (.ex, .exs)
pub struct ElixirAnalyzer {
    /// Dynamic callbacks table built by scanning dep source files.
    /// Maps fully-qualified module name → list of (fn_name, arity) pairs
    /// that are declared `defoverridable` inside that module's `__using__`
    /// or `__before_compile__` macro.
    /// When `use SomeModule` is seen in user code, any definition matching
    /// an entry here is treated as implicitly called.
    dep_callbacks: std::collections::HashMap<String, Vec<(String, usize)>>,

    /// `def function_name(args)` or `defp function_name(args)`
    def_re: Regex,
    /// `def function_name, do: ...` (zero-arg shorthand)
    def_no_parens_re: Regex,
    /// Bare call: `some_function(args)` — local calls
    call_re: Regex,
    /// Pipe call: `|> some_function(args)` — piped calls (arity is args+1)
    pipe_call_re: Regex,
    /// Pipe call without parens: `|> some_function` — arity is always 1 (piped value only)
    pipe_call_no_parens_re: Regex,
    /// Remote call: `Module.function(args)` or `A.B.C.function(args)`
    remote_call_re: Regex,
    /// Pipe into remote call: `|> Module.function(args)` — arity is args+1
    pipe_remote_call_re: Regex,
    /// Capture: `&Module.function/arity` or `&local_function/arity`
    capture_re: Regex,
    /// Detects `apply(module, :fn_name, [arg, ...])` and
    /// `Kernel.apply(module, :fn_name, [arg, ...])` calls.
    /// Group 1: the function name atom.
    /// Group 2: the contents of the args list (used to count arity).
    apply_re: Regex,
    /// Detects `use SomeBehaviour` or `@behaviour SomeBehaviour` declarations
    behaviour_re: Regex,
    /// Detects any `use Module.Name` line and captures the full dotted module name.
    /// Used to look up dep_callbacks — behaviour_re only captures the last segment
    /// which is insufficient for namespaced modules like `Waffle.Definition`.
    /// Capture group 1: the full module name (e.g. "Waffle.Definition").
    use_module_re: Regex,
    /// Detects `use Module, :atom` — the Phoenix convention where the atom
    /// names a zero-arity function (`def view`, `def controller`, etc.) defined
    /// in the used module that returns a `quote` block.
    /// Capture group 1: the atom name (without the leading colon).
    use_atom_re: Regex,
    /// Detects Phoenix router route macros:
    ///   get "/path", SomeController, :action
    ///   get "/path", SomeController, :action, as: :name
    /// Captures the action atom so we can synthesize an implicit call.
    router_route_re: Regex,
    /// Detects a `scope` macro line and captures its optional `as: :name`.
    /// Used to track the active alias prefix stack for helper name generation.
    ///   scope "/api/public", V5ApiWeb.Public, as: :public do
    /// Capture group 1: the alias atom if present, or no match if absent.
    router_scope_re: Regex,
    /// Detects an `as: :name` option on a route line (verb macros only, not
    /// scope — those are handled by router_scope_re).  Combined with the active
    /// scope prefix stack to produce fully-qualified helper names.
    /// Capture group 1: the alias atom name (without the leading colon).
    router_as_re: Regex,
}

impl ElixirAnalyzer {
    pub fn new() -> Self {
        Self {
            dep_callbacks: std::collections::HashMap::new(),

            // Matches: def(p) name(arg1, arg2, ...) [when ...]
            // [^\S\n]* matches horizontal whitespace only (not newlines), so
            // (?m)^ + [^\S\n]* cannot bleed across lines the way \s* can.
            def_re: Regex::new(
                r"(?m)^[^\S\n]*def(p?)\s+([a-z_][a-zA-Z0-9_!?]*)\s*\(([^)]*)\)"
            ).unwrap(),

            // Matches: def(p) name, do: ... (zero-arg shorthand without parens)
            def_no_parens_re: Regex::new(
                r"(?m)^[^\S\n]*def(p?)\s+([a-z_][a-zA-Z0-9_!?]*)\s*,"
            ).unwrap(),

            // Matches any function call: name(...)
            // Excludes control-flow keywords, module attributes, and def forms
            call_re: Regex::new(
                r"(?m)\b([a-z_][a-zA-Z0-9_!?]*)\s*\("
            ).unwrap(),

            // Matches pipe calls: |> function_name(
            // We only need the name — arity is computed by counting args in the source
            pipe_call_re: Regex::new(
                r"\|>\s*([a-z_][a-zA-Z0-9_!?]*)\s*\("
            ).unwrap(),

            // Matches no-parens pipe calls without parens: `|> function_name`
            // e.g. `"test" |> validate` — arity is always 1 (piped value only).
            // Group 1: function name.
            // Group 2: captures `(` or `.` if immediately following (after optional
            // whitespace) so the collection pass can skip those cases — they are
            // handled by pipe_call_re and pipe_remote_call_re respectively.
            // Using [(.] instead of \S? avoids matching newlines and other chars.
            pipe_call_no_parens_re: Regex::new(
                r"\|>\s*([a-z_][a-zA-Z0-9_!?]*)\s*([(.)]?)"
            ).unwrap(),

            // Matches remote calls: Some.Module.function(
            // Captures just the function name (last segment after the final dot)
            remote_call_re: Regex::new(
                r"(?:[A-Z][a-zA-Z0-9_]*\.)+([a-z_][a-zA-Z0-9_!?]*)\s*\("
            ).unwrap(),

            // Matches pipe-into-remote calls: |> Some.Module.function(
            // Arity is explicit args + 1 (the piped value)
            pipe_remote_call_re: Regex::new(
                r"\|>\s*(?:[A-Z][a-zA-Z0-9_]*\.)+([a-z_][a-zA-Z0-9_!?]*)\s*\("
            ).unwrap(),

            // Matches function captures: &Module.function/arity or &local_fn/arity
            // e.g. `&Mutations.Send.send/2` or `&my_helper/1`
            capture_re: Regex::new(
                r"&(?:(?:[A-Z][a-zA-Z0-9_]*\.)+)?([a-z_][a-zA-Z0-9_!?]*)/(\d+)"
            ).unwrap(),

            // Matches apply(module, :fn_name, args) and Kernel.apply(...) calls.
            // The first argument (module) is skipped — we only care about the name
            // atom and the args so we can compute arity where possible.
            // Group 1: function name atom (without leading colon).
            // Group 2: contents of a literal args list `[...]`, if present.
            //          Absent when the third arg is a variable or expression —
            //          in that case arity is unknown (None).
            // Examples:
            //   apply(module, :authorize_url!, [opts])  → authorize_url!/1
            //   apply(__MODULE__, :process, [a, b])     → process/2
            //   apply(mod, :fetch!, args)               → fetch!/None (unknown arity)
            //   Kernel.apply(mod, :reset, [])           → reset/0
            apply_re: Regex::new(
                r"(?:Kernel\.)?apply\([^,]+,\s*:([a-z_][a-zA-Z0-9_!?]*),\s*(?:\[([^\]]*)\]|[a-z_][a-zA-Z0-9_]*)"
            ).unwrap(),

            // Matches `use Module` or `@behaviour Module` to detect OTP behaviours.
            // Captures the final module segment, e.g. "Application" from "use Application"
            // or "GenServer" from "use GenServer" / "@behaviour GenServer".
            behaviour_re: Regex::new(
                r"(?:use|@behaviour)\s+(?:[A-Z][a-zA-Z0-9_]*\.)*([A-Z][a-zA-Z0-9_]*)"
            ).unwrap(),

            // Captures the full dotted module name from any `use Module.Name` line,
            // including optional trailing arguments (ignored here).
            // Used to key into dep_callbacks for defoverridable lookup.
            use_module_re: Regex::new(
                r"(?m)^\s*use\s+((?:[A-Z][a-zA-Z0-9_]*\.)*[A-Z][a-zA-Z0-9_]*)"
            ).unwrap(),

            // Matches `use SomeModule, :atom` — Phoenix's convention for selecting
            // a zero-arity macro-generator function by atom name, e.g.:
            //   use MyAppWeb, :view        →  calls view/0
            //   use MyAppWeb, :controller  →  calls controller/0
            // Capture group 1: the atom name.
            use_atom_re: Regex::new(
                r"(?m)^\s*use\s+[A-Z][a-zA-Z0-9_.]*,\s*:([a-z_][a-zA-Z0-9_]*)"
            ).unwrap(),

            // Matches Phoenix router route macros and captures the action atom.
            // Handles all HTTP verb macros and `live`, `resources`, `websocket` etc.
            // Examples:
            //   get  "/path", PageController, :index
            //   post "/path", SessionController, :create, as: :login
            //   live "/path", MyLive, :index
            // Capture group 1: the action atom name (without the leading colon).
            router_route_re: Regex::new(
                r#"(?m)^\s*(?:get|post|put|patch|delete|options|head|connect|trace|live|resources|websocket|channel)\s+"[^"]*",\s*[A-Z][a-zA-Z0-9_.]*,\s*:([a-z_][a-zA-Z0-9_!?]*)"#
            ).unwrap(),

            // Matches a `scope` line. We only need to confirm the line IS a scope
            // line — the `as: :name` alias is extracted separately by router_as_re.
            //   scope "/api/public", V5ApiWeb.Public, as: :public do
            //   scope "/api" do
            router_scope_re: Regex::new(
                r#"(?m)^\s*scope\s+"[^"]*""#
            ).unwrap(),

            // Matches `as: :name` on a route verb line (not scope — those are
            // handled above).  Used together with the active scope prefix to form
            // a fully-qualified helper name, e.g. `public_current` from scope
            // prefix `public` and route alias `current`.
            // Capture group 1: the alias atom name (without the leading colon).
            router_as_re: Regex::new(
                r"\bas:\s*:([a-z_][a-zA-Z0-9_]*)"
            ).unwrap(),
        }
    }

    /// Build a new analyzer that has scanned `deps_path` for `defoverridable`
    /// declarations inside `__using__` / `__before_compile__` macros.
    ///
    /// Call this instead of `new()` when a deps directory is available:
    ///   let analyzer = ElixirAnalyzer::new().with_deps(Path::new("deps"));
    pub fn with_deps(mut self, deps_path: &Path) -> Self {
        if let Ok(table) = Self::scan_deps(deps_path) {
            self.dep_callbacks = table;
        }
        self
    }

    /// Print the dep_callbacks table and edge graph to stderr for debugging.
    /// Invoke via `--debug-deps` on the CLI to diagnose missing callback detection.
    pub fn dump_dep_callbacks(&self) {
        if self.dep_callbacks.is_empty() {
            eprintln!("[dep_callbacks] empty — no callbacks found in deps");
        } else {
            let mut modules: Vec<&String> = self.dep_callbacks.keys().collect();
            modules.sort();
            for module in modules {
                let cbs = &self.dep_callbacks[module];
                eprintln!("[dep_callbacks] {}:", module);
                let mut sorted = cbs.clone();
                sorted.sort();
                for (name, arity) in sorted {
                    eprintln!("  {}/{}", name, arity);
                }
            }
        }
    }

    /// Extended debug: also dumps raw scan results before propagation.
    /// Call this from a test or debug build to diagnose scan issues.
    pub fn debug_scan_deps(deps_path: &Path) {
        eprintln!("[scan_deps] scanning: {}", deps_path.display());

        let defmodule_re =
            Regex::new(r"(?m)^\s*defmodule\s+((?:[A-Z][a-zA-Z0-9_]*\.)*[A-Z][a-zA-Z0-9_]*)")
                .unwrap();
        let using_open_re = Regex::new(r"(?m)^\s*defmacro\s+__using__").unwrap();
        let before_compile_open_re = Regex::new(r"(?m)^\s*defmacro\s+__before_compile__").unwrap();

        for entry in walkdir::WalkDir::new(deps_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_type().is_file()
                    && e.path()
                        .extension()
                        .map_or(false, |ext| ext == "ex" || ext == "exs")
            })
        {
            let raw = match std::fs::read_to_string(entry.path()) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let source = Self::strip_heredocs(&raw);

            let has_using = using_open_re.is_match(&source);
            let has_before_compile = before_compile_open_re.is_match(&source);
            let has_defoverridable = source.contains("defoverridable");

            if !has_using && !has_before_compile && !has_defoverridable {
                continue;
            }

            let modules: Vec<String> = defmodule_re
                .captures_iter(&source)
                .map(|c| c.get(1).unwrap().as_str().to_string())
                .collect();

            eprintln!(
                "[scan_deps] {:?}  modules={:?}  __using__={}  __before_compile__={}  defoverridable={}",
                entry.path(),
                modules,
                has_using,
                has_before_compile,
                has_defoverridable,
            );
        }
    }

    /// Replace the content of every `"""..."""` heredoc in `source` with
    /// whitespace, preserving line count so byte positions of code outside
    /// heredocs remain valid.  This prevents `@moduledoc` / `@doc` example
    /// code from being matched as real `defmacro`, `defoverridable`, or `def`
    /// declarations during dep scanning.
    fn strip_heredocs(source: &str) -> String {
        let mut result = String::with_capacity(source.len());
        let bytes = source.as_bytes();
        let len = bytes.len();
        let mut i = 0;

        while i < len {
            // Look for the opening `"""`.
            if i + 2 < len && bytes[i] == b'"' && bytes[i + 1] == b'"' && bytes[i + 2] == b'"' {
                // Emit the opening delimiter verbatim so positions stay anchored.
                result.push_str(r#"""""#);
                i += 3;

                // Replace everything up to the closing `"""` with spaces/newlines.
                while i < len {
                    if i + 2 < len
                        && bytes[i] == b'"'
                        && bytes[i + 1] == b'"'
                        && bytes[i + 2] == b'"'
                    {
                        result.push_str(r#"""""#);
                        i += 3;
                        break;
                    }
                    // Preserve newlines so line numbers stay accurate; blank other chars.
                    if bytes[i] == b'\n' {
                        result.push('\n');
                    } else {
                        result.push(' ');
                    }
                    i += 1;
                }
            } else {
                result.push(bytes[i] as char);
                i += 1;
            }
        }

        result
    }

    /// Walk `deps_path` recursively, parsing every `.ex` / `.exs` file for
    /// `defoverridable` declarations and `def` injections inside
    /// `__using__` / `__before_compile__` macros, then propagate callbacks
    /// transitively through `use` and `@before_compile` chains.
    ///
    /// Returns a map of fully-qualified-module-name → [(fn_name, arity)].
    fn scan_deps(
        deps_path: &Path,
    ) -> Result<std::collections::HashMap<String, Vec<(String, usize)>>> {
        let defmodule_re =
            Regex::new(r"(?m)^\s*defmodule\s+((?:[A-Z][a-zA-Z0-9_]*\.)*[A-Z][a-zA-Z0-9_]*)")
                .unwrap();
        // Distinguishes __using__ from __before_compile__ so we know which
        // collection strategy to apply to each macro body.
        let using_open_re = Regex::new(r"(?m)^\s*defmacro\s+__using__").unwrap();
        let before_compile_open_re = Regex::new(r"(?m)^\s*defmacro\s+__before_compile__").unwrap();
        // defoverridable keyword list, possibly multiline.
        let defoverridable_kw_re =
            Regex::new(r"defoverridable\s+((?:[a-z_][a-zA-Z0-9_!?]*:\s*\d+[\s,]*)+)").unwrap();
        let pair_re = Regex::new(r"([a-z_][a-zA-Z0-9_!?]*):\s*(\d+)").unwrap();
        // `use Some.Module` inside a macro body → transitive use edge.
        let use_re =
            Regex::new(r"(?m)^\s*use\s+((?:[A-Z][a-zA-Z0-9_]*\.)*[A-Z][a-zA-Z0-9_]*)").unwrap();
        // `@before_compile Some.Module` inside a macro body → compile-time edge.
        let before_compile_attr_re =
            Regex::new(r"@before_compile\s+((?:[A-Z][a-zA-Z0-9_]*\.)*[A-Z][a-zA-Z0-9_]*)").unwrap();
        // `def name(args)` or `def name(args), do:` inside a quote block.
        // We only need the function name and arg count — same pattern as def_re
        // but without the line-start anchor since it's inside a string body.
        let injected_def_re =
            Regex::new(r"def(p?)\s+([a-z_][a-zA-Z0-9_!?]*)\s*\(([^)]*)\)").unwrap();

        // direct_callbacks: module → callbacks declared via defoverridable OR
        // injected as def defaults inside __before_compile__.
        let mut direct_callbacks: std::collections::HashMap<String, Vec<(String, usize)>> =
            std::collections::HashMap::new();

        // edges: module A → [module B, ...] meaning A's __using__ body calls
        // `use B` or sets `@before_compile B`, so B's callbacks propagate to A.
        let mut edges: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();

        for entry in walkdir::WalkDir::new(deps_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_type().is_file()
                    && e.path()
                        .extension()
                        .map_or(false, |ext| ext == "ex" || ext == "exs")
            })
        {
            let raw = match std::fs::read_to_string(entry.path()) {
                Ok(s) => s,
                Err(_) => continue,
            };
            // Strip heredoc strings before scanning so that example code in
            // @moduledoc / @doc blocks doesn't match defmacro, defoverridable, etc.
            let source = Self::strip_heredocs(&raw);

            let module_positions: Vec<(usize, String)> = defmodule_re
                .captures_iter(&source)
                .map(|c| {
                    (
                        c.get(0).unwrap().start(),
                        c.get(1).unwrap().as_str().to_string(),
                    )
                })
                .collect();

            if module_positions.is_empty() {
                continue;
            }

            let owner_at = |pos: usize| -> Option<String> {
                module_positions
                    .iter()
                    .filter(|(p, _)| *p <= pos)
                    .last()
                    .map(|(_, name)| name.clone())
            };

            // --- Process __using__ macro bodies ---
            // Collect: defoverridable pairs, `use` edges, `@before_compile` edges.
            for mac in using_open_re.find_iter(&source) {
                let owner = match owner_at(mac.start()) {
                    Some(n) => n,
                    None => continue,
                };
                let body = &source[mac.start()..];

                for kw_cap in defoverridable_kw_re.captures_iter(body) {
                    let pairs: Vec<(String, usize)> = pair_re
                        .captures_iter(kw_cap.get(1).unwrap().as_str())
                        .map(|c| {
                            (
                                c.get(1).unwrap().as_str().to_string(),
                                c.get(2).unwrap().as_str().parse().unwrap_or(0),
                            )
                        })
                        .collect();
                    if !pairs.is_empty() {
                        direct_callbacks
                            .entry(owner.clone())
                            .or_default()
                            .extend(pairs);
                    }
                }
                for cap in use_re.captures_iter(body) {
                    let used = cap.get(1).unwrap().as_str().to_string();
                    if used != owner {
                        edges.entry(owner.clone()).or_default().push(used);
                    }
                }
                for cap in before_compile_attr_re.captures_iter(body) {
                    let target = cap.get(1).unwrap().as_str().to_string();
                    if target != owner {
                        edges.entry(owner.clone()).or_default().push(target);
                    }
                }
            }

            // --- Process __before_compile__ macro bodies ---
            // Every public `def` injected here is a default implementation that the
            // library calls by name — treat each one as an implicit overridable callback.
            for mac in before_compile_open_re.find_iter(&source) {
                let owner = match owner_at(mac.start()) {
                    Some(n) => n,
                    None => continue,
                };
                let body = &source[mac.start()..];

                // Collect explicit defoverridable (rare but possible).
                for kw_cap in defoverridable_kw_re.captures_iter(body) {
                    let pairs: Vec<(String, usize)> = pair_re
                        .captures_iter(kw_cap.get(1).unwrap().as_str())
                        .map(|c| {
                            (
                                c.get(1).unwrap().as_str().to_string(),
                                c.get(2).unwrap().as_str().parse().unwrap_or(0),
                            )
                        })
                        .collect();
                    if !pairs.is_empty() {
                        direct_callbacks
                            .entry(owner.clone())
                            .or_default()
                            .extend(pairs);
                    }
                }

                // Collect every injected public def as an implicit callback.
                for cap in injected_def_re.captures_iter(body) {
                    let is_private = cap.get(1).unwrap().as_str() == "p";
                    if is_private {
                        continue;
                    }
                    let name = cap.get(2).unwrap().as_str().to_string();
                    let arity = Self::count_args(cap.get(3).unwrap().as_str());
                    direct_callbacks
                        .entry(owner.clone())
                        .or_default()
                        .push((name, arity));
                }
            }
        }

        // Propagate callbacks transitively through edges (fixed-point).
        // Seed the table with direct callbacks; merge inherited ones until stable.
        let mut table = direct_callbacks.clone();
        let all_modules: Vec<String> = table
            .keys()
            .cloned()
            .chain(edges.keys().cloned())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let mut changed = true;
        while changed {
            changed = false;
            for module in &all_modules {
                if let Some(deps_list) = edges.get(module) {
                    let inherited: Vec<(String, usize)> = deps_list
                        .iter()
                        .flat_map(|dep| table.get(dep).cloned().unwrap_or_default())
                        .collect();
                    if !inherited.is_empty() {
                        let entry = table.entry(module.clone()).or_default();
                        for cb in inherited {
                            if !entry.contains(&cb) {
                                entry.push(cb);
                                changed = true;
                            }
                        }
                    }
                }
            }
        }

        Ok(table)
    }

    /// Given source bytes and the position of an opening `(`, extract the
    /// contents up to the matching `)` and return the arg string.
    /// Returns None if the paren is unmatched (malformed source).
    fn extract_args(source: &str, open_paren: usize) -> Option<&str> {
        let bytes = source.as_bytes();
        let mut depth = 0i32;
        let mut i = open_paren;
        while i < bytes.len() {
            match bytes[i] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        // +1 to skip the `(`, i is the closing `)`
                        return Some(&source[open_paren + 1..i]);
                    }
                }
                _ => {}
            }
            i += 1;
        }
        None
    }

    /// Returns the set of byte ranges covered by definition lines, used to
    /// avoid treating `def foo(x)` as a call to `foo`.
    fn def_line_ranges(
        source: &str,
        def_re: &Regex,
        def_no_parens_re: &Regex,
    ) -> Vec<std::ops::Range<usize>> {
        let mut ranges = Vec::new();
        for cap in def_re.captures_iter(source) {
            let m = cap.get(0).unwrap();
            ranges.push(m.start()..m.end());
        }
        for cap in def_no_parens_re.captures_iter(source) {
            let m = cap.get(0).unwrap();
            ranges.push(m.start()..m.end());
        }
        ranges
    }

    fn in_def_line(byte: usize, ranges: &[std::ops::Range<usize>]) -> bool {
        ranges.iter().any(|r| r.contains(&byte))
    }

    /// Count the number of top-level arguments in a comma-separated arg string.
    fn count_args(args: &str) -> usize {
        let trimmed = args.trim();
        if trimmed.is_empty() {
            return 0;
        }
        // Simple heuristic: count top-level commas (not inside nested parens/brackets)
        let mut depth: i32 = 0;
        let mut count = 1usize;
        for ch in trimmed.chars() {
            match ch {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth -= 1,
                ',' if depth == 0 => count += 1,
                _ => {}
            }
        }
        count
    }

    /// Count the number of parameters with default values (`\\`) at the top
    /// level of an argument string.  For example:
    ///   `a, b \\ true, c \\ nil`  → 2
    ///   `opts \\ []`               → 1
    ///   `a, b`                     → 0
    ///
    /// We scan for the two-character sequence `\\` only at depth 0 so that
    /// defaults buried inside tuple/list/map literals are not double-counted.
    fn count_defaults(args: &str) -> usize {
        let trimmed = args.trim();
        if trimmed.is_empty() {
            return 0;
        }
        let mut depth: i32 = 0;
        let mut count = 0usize;
        let chars: Vec<char> = trimmed.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            match chars[i] {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth -= 1,
                '\\' if depth == 0 && chars.get(i + 1) == Some(&'\\') => {
                    count += 1;
                    i += 2; // skip both backslashes
                    continue;
                }
                _ => {}
            }
            i += 1;
        }
        count
    }

    /// Collect line-start byte offsets so we can map byte positions → line numbers
    fn line_starts(source: &str) -> Vec<usize> {
        let mut starts = vec![0usize];
        for (i, ch) in source.char_indices() {
            if ch == '\n' {
                starts.push(i + 1);
            }
        }
        starts
    }

    fn byte_to_line(line_starts: &[usize], byte: usize) -> usize {
        match line_starts.binary_search(&byte) {
            Ok(line) => line + 1,
            Err(line) => line,
        }
    }
}

/// Well-known OTP/Phoenix behaviour callbacks keyed by the last module segment.
/// Each entry is `(behaviour_name, &[(callback_name, arity)])`.
/// A function matching any of these is implicitly "called" by the runtime and
/// must never be reported as unused.
const BEHAVIOUR_CALLBACKS: &[(&str, &[(&str, usize)])] = &[
    (
        "Application",
        &[
            ("start", 2),
            ("stop", 1),
            ("prep_stop", 1),
            ("config_change", 3),
            ("start_phase", 3),
        ],
    ),
    (
        "GenServer",
        &[
            ("init", 1),
            ("handle_call", 3),
            ("handle_cast", 2),
            ("handle_info", 2),
            ("handle_continue", 2),
            ("terminate", 2),
            ("code_change", 3),
            ("format_status", 2),
        ],
    ),
    (
        "GenStateMachine",
        &[
            ("init", 1),
            ("callback_mode", 0),
            ("handle_event", 4),
            ("terminate", 3),
            ("code_change", 4),
            ("format_status", 2),
        ],
    ),
    ("Supervisor", &[("init", 1)]),
    (
        "GenEvent",
        &[
            ("init", 1),
            ("handle_event", 2),
            ("handle_call", 2),
            ("handle_info", 2),
            ("terminate", 2),
            ("code_change", 3),
        ],
    ),
    // Phoenix
    (
        "Phoenix.LiveView",
        &[
            ("mount", 3),
            ("render", 1),
            ("handle_event", 3),
            ("handle_info", 2),
            ("handle_cast", 2),
            ("handle_call", 3),
            ("handle_async", 3),
            ("update", 2),
            ("terminate", 2),
        ],
    ),
    (
        "Phoenix.Channel",
        &[
            ("join", 3),
            ("handle_in", 3),
            ("handle_out", 3),
            ("handle_info", 2),
            ("terminate", 2),
        ],
    ),
    ("Plug", &[("init", 1), ("call", 2)]),
    (
        "Ecto.Type",
        &[
            ("type", 0),
            ("cast", 1),
            ("load", 1),
            ("dump", 1),
            ("equal?", 2),
            ("embed_as", 1),
        ],
    ),
];

/// Note: `send` and `spawn` are deliberately excluded — they are common user-defined
/// function names and are also Kernel functions, but the analyzer works at the name
/// level not the module level, so filtering them causes false negatives.
const ELIXIR_KEYWORDS: &[&str] = &[
    "def",
    "defp",
    "defmodule",
    "defmacro",
    "defmacrop",
    "defprotocol",
    "defimpl",
    "defstruct",
    "defexception",
    "defdelegate",
    "defoverridable",
    "if",
    "unless",
    "case",
    "cond",
    "with",
    "for",
    "try",
    "receive",
    "do",
    "end",
    "fn",
    "when",
    "and",
    "or",
    "not",
    "in",
    "true",
    "false",
    "nil",
    "raise",
    "reraise",
    "throw",
    "exit",
    "import",
    "alias",
    "require",
    "use",
];

impl LanguageAnalyzer for ElixirAnalyzer {
    fn name(&self) -> &'static str {
        "Elixir"
    }

    fn extensions(&self) -> &[&'static str] {
        &["ex", "exs"]
    }

    fn analyze_file(&self, path: &Path) -> Result<FileAnalysis> {
        let source = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;

        let file_str = path.to_string_lossy().into_owned();
        let line_starts = Self::line_starts(&source);

        let mut definitions: Vec<FunctionDef> = Vec::new();
        let mut calls: Vec<FunctionCall> = Vec::new();

        // Side-table: for each function that has default args, record the full
        // arity range it covers.  Used later to synthesize implicit delegation
        // calls (e.g. foo/0 → foo/1 when `def foo(opts \\ [])` is the header).
        // Keyed by (name, max_arity) → min_arity.
        let mut default_ranges: Vec<(String, usize, usize)> = Vec::new(); // (name, max, min)

        // --- Collect definitions (with parens) ---
        for cap in self.def_re.captures_iter(&source) {
            let is_private = cap.get(1).map_or("", |m| m.as_str()) == "p";
            let name = cap.get(2).unwrap().as_str().to_string();
            let args_str = cap.get(3).unwrap().as_str();
            let arity = Self::count_args(args_str);
            let defaults = Self::count_defaults(args_str);
            let byte = cap.get(0).unwrap().start();
            let line = Self::byte_to_line(&line_starts, byte);

            // A definition with `n` default args implicitly accepts calls with
            // arity in `(arity - n) ..= arity`.  Emit a FunctionDef for every
            // arity in that range so cross-reference matching works correctly.
            let min_arity = arity.saturating_sub(defaults);
            for effective_arity in min_arity..=arity {
                definitions.push(FunctionDef {
                    name: name.clone(),
                    arity: Some(effective_arity),
                    line,
                    file: file_str.clone(),
                    is_private,
                });
            }

            if defaults > 0 {
                // Record only if this is the highest-arity entry we've seen for
                // this name (a later clause body won't have defaults in its
                // signature, so the header clause always has the widest range).
                if !default_ranges
                    .iter()
                    .any(|(n, max, _)| n == &name && *max == arity)
                {
                    default_ranges.push((name.clone(), arity, min_arity));
                }
                // The compiler generates hidden lower-arity clauses that
                // unconditionally delegate to the full-arity body.  Every arity
                // in the range [min_arity..=max_arity] is implicitly "used" by
                // this machinery — none of them require an explicit call site.
                for implicit_arity in min_arity..=arity {
                    calls.push(FunctionCall {
                        name: name.clone(),
                        arity: Some(implicit_arity),
                        line: 0, // synthetic
                        file: file_str.clone(),
                    });
                }
            }
        }

        // --- Collect zero-arg definitions (def name, do: ...) ---
        for cap in self.def_no_parens_re.captures_iter(&source) {
            let is_private = cap.get(1).map_or("", |m| m.as_str()) == "p";
            let name = cap.get(2).unwrap().as_str().to_string();
            let byte = cap.get(0).unwrap().start();
            let line = Self::byte_to_line(&line_starts, byte);

            // Only add if not already captured by def_re
            let already_captured = definitions
                .iter()
                .any(|d| d.name == name && d.arity == Some(0) && d.line == line);

            if !already_captured {
                definitions.push(FunctionDef {
                    name,
                    arity: Some(0),
                    line,
                    file: file_str.clone(),
                    is_private,
                });
            }
        }

        // Pre-compute which byte ranges are definition headers so we don't
        // emit a call for e.g. `foo` in `def foo(x), do: ...`
        let def_ranges = Self::def_line_ranges(&source, &self.def_re, &self.def_no_parens_re);

        // --- Synthesize implicit calls for OTP/behaviour callbacks ---
        // Any function that implements a behaviour contract is "called" by the
        // runtime; emit a phantom call so it is never flagged as unused.
        for cap in self.behaviour_re.captures_iter(&source) {
            let behaviour = cap.get(1).unwrap().as_str();
            if let Some((_, callbacks)) = BEHAVIOUR_CALLBACKS
                .iter()
                .find(|(name, _)| *name == behaviour)
            {
                for (cb_name, cb_arity) in *callbacks {
                    // Only emit if the module actually defines this callback.
                    if definitions
                        .iter()
                        .any(|d| d.name == *cb_name && d.arity == Some(*cb_arity))
                    {
                        calls.push(FunctionCall {
                            name: cb_name.to_string(),
                            arity: Some(*cb_arity),
                            // Line 0 signals a synthetic/implicit call site.
                            line: 0,
                            file: file_str.clone(),
                        });
                    }
                }
            }
        }

        // --- Synthesize implicit calls for dep-scanned `defoverridable` callbacks ---
        // For each `use Some.Module` in the current file, look up the full module
        // name in dep_callbacks and emit a synthetic call for every matching def.
        for cap in self.use_module_re.captures_iter(&source) {
            let module_name = cap.get(1).unwrap().as_str();
            if let Some(callbacks) = self.dep_callbacks.get(module_name) {
                for (cb_name, cb_arity) in callbacks {
                    if definitions
                        .iter()
                        .any(|d| d.name == *cb_name && d.arity == Some(*cb_arity))
                    {
                        calls.push(FunctionCall {
                            name: cb_name.clone(),
                            arity: Some(*cb_arity),
                            line: 0,
                            file: file_str.clone(),
                        });
                    }
                }
            }
        }

        // `use MyAppWeb, :view` compiles to `MyAppWeb.__using__(:view)` which
        // by Phoenix convention dispatches to the zero-arity function named by
        // the atom (`view/0`, `controller/0`, etc.) in that module.  Emit a
        // call to `atom/0` so those definition-only functions are not flagged.
        for cap in self.use_atom_re.captures_iter(&source) {
            let fn_name = cap.get(1).unwrap().as_str();
            let byte = cap.get(0).unwrap().start();
            let line = Self::byte_to_line(&line_starts, byte);
            calls.push(FunctionCall {
                name: fn_name.to_string(),
                arity: Some(0),
                line,
                file: file_str.clone(),
            });
        }

        // --- Synthesize implicit calls for Phoenix router action atoms ---
        // `get "/path", SomeController, :action` means Phoenix will call
        // `SomeController.action(conn, params)` at runtime.  Since the
        // controller lives in a different module we can only record the
        // function *name*; the arity is always 2 (conn + params).
        for cap in self.router_route_re.captures_iter(&source) {
            let action = cap.get(1).unwrap().as_str();
            let byte = cap.get(0).unwrap().start();
            let line = Self::byte_to_line(&line_starts, byte);
            calls.push(FunctionCall {
                name: action.to_string(),
                arity: Some(2),
                line,
                file: file_str.clone(),
            });
        }

        // --- Synthesize macro-generated definitions for route `as:` helpers ---
        // Only meaningful in Phoenix router files. We gate the entire pass on
        // detecting `use Phoenix.Router` (or any `use ...Router`) in the source
        // to avoid misinterpreting `as:` options in non-router files.
        //
        // Phoenix generates `{scope_prefix_}name_path/2,3` and `_url` variants
        // for every route `as: :name`, where the prefix comes from all enclosing
        // `scope ... as: :foo` blocks joined with `_`.
        //
        // We track only `scope` block depth — not every `do`/`end` in the file —
        // by maintaining a stack of scope aliases.  Each `scope ... do` line
        // pushes an entry (the alias or "" if no `as:`); each line that is solely
        // `end` (possibly with leading whitespace) and whose nesting depth matches
        // a scope entry pops it.  We count *all* `do`-block opens so the `end`
        // counter stays balanced, but only scope entries contribute to the prefix.
        let is_router_file = source.contains("use Phoenix.Router")
            || source.contains("use ") && source.contains("Router");

        if is_router_file {
            // scope_stack: (alias_contribution, open_block_depth_at_push)
            // We push one entry per open block (scope or other) and annotate
            // whether it is a scope block.  This way `end` always pops exactly
            // one entry regardless of block type.
            let mut scope_stack: Vec<Option<String>> = Vec::new();

            // Regex to detect any `do`-block-opening line (used for non-scope
            // blocks so we still push a placeholder and keep `end` counts right).
            // A line opens a block if it ends with a bare `do` word — but NOT
            // if it is a single-line `do:` form.
            let opens_block = |line: &str| -> bool {
                let t = line.trim_end();
                // Single-line forms like `def foo, do: x` do NOT open a block.
                // Block-opening forms end with ` do` or just `do` alone.
                (t.ends_with(" do") || t == "do") && !t.ends_with("do:")
            };

            let closes_block = |line: &str| -> bool {
                // A line that is just `end` (plus optional whitespace/comments)
                // closes exactly one block.
                line.trim() == "end"
            };

            for line in source.lines() {
                // Pop before push so an `end` on its own line is processed first.
                if closes_block(line) {
                    scope_stack.pop();
                    continue;
                }

                let is_scope = self.router_scope_re.is_match(line);

                if is_scope {
                    let alias = self
                        .router_as_re
                        .captures(line)
                        .and_then(|c| c.get(1))
                        .map(|m| m.as_str().to_string());
                    scope_stack.push(alias); // Some("foo") or None
                } else if opens_block(line) {
                    scope_stack.push(None); // non-scope block; no prefix contribution
                }

                // Emit helpers for route lines that carry their own `as:`.
                if self.router_route_re.is_match(line) {
                    if let Some(cap) = self.router_as_re.captures(line) {
                        let route_alias = cap.get(1).unwrap().as_str();

                        // Build prefix from all Some(alias) entries on the stack.
                        let prefix: String = scope_stack
                            .iter()
                            .filter_map(|e| e.as_deref())
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>()
                            .join("_");

                        let full_alias = if prefix.is_empty() {
                            route_alias.to_string()
                        } else {
                            format!("{}_{}", prefix, route_alias)
                        };

                        let line_no = Self::byte_to_line(
                            &line_starts,
                            // approximate: find this line's byte offset
                            source.find(line).unwrap_or(0),
                        );
                        for suffix in &["_path", "_url"] {
                            let helper_name = format!("{}{}", full_alias, suffix);
                            for arity in 2..=3usize {
                                definitions.push(FunctionDef {
                                    name: helper_name.clone(),
                                    arity: Some(arity),
                                    line: line_no,
                                    file: file_str.clone(),
                                    is_private: false,
                                });
                            }
                        }
                    }
                }
            }
        }

        // --- Collect call sites ---
        for cap in self.call_re.captures_iter(&source) {
            let name = cap.get(1).unwrap().as_str();
            if ELIXIR_KEYWORDS.contains(&name) {
                continue;
            }
            let open_paren = cap.get(0).unwrap().end() - 1; // position of `(`
            let byte = cap.get(0).unwrap().start();

            // Skip if this match sits inside a def header
            if Self::in_def_line(byte, &def_ranges) {
                continue;
            }

            let args_str = Self::extract_args(&source, open_paren).unwrap_or("");
            let arity = Self::count_args(args_str);
            let line = Self::byte_to_line(&line_starts, byte);

            calls.push(FunctionCall {
                name: name.to_string(),
                arity: Some(arity),
                line,
                file: file_str.clone(),
            });
        }

        // --- Collect pipe-call sites (arity += 1 due to piped value) ---
        for cap in self.pipe_call_re.captures_iter(&source) {
            let name = cap.get(1).unwrap().as_str();
            if ELIXIR_KEYWORDS.contains(&name) {
                continue;
            }
            let open_paren = cap.get(0).unwrap().end() - 1;
            let byte = cap.get(0).unwrap().start();
            let args_str = Self::extract_args(&source, open_paren).unwrap_or("");
            let explicit_args = Self::count_args(args_str);
            let arity = if args_str.trim().is_empty() {
                1
            } else {
                explicit_args + 1
            };
            let line = Self::byte_to_line(&line_starts, byte);

            calls.push(FunctionCall {
                name: name.to_string(),
                arity: Some(arity),
                line,
                file: file_str.clone(),
            });
        }

        // --- Collect remote calls: Some.Module.fn(args) ---
        for cap in self.remote_call_re.captures_iter(&source) {
            let name = cap.get(1).unwrap().as_str();
            if ELIXIR_KEYWORDS.contains(&name) {
                continue;
            }
            let open_paren = cap.get(0).unwrap().end() - 1;
            let byte = cap.get(0).unwrap().start();
            let args_str = Self::extract_args(&source, open_paren).unwrap_or("");
            let arity = Self::count_args(args_str);
            let line = Self::byte_to_line(&line_starts, byte);

            calls.push(FunctionCall {
                name: name.to_string(),
                arity: Some(arity),
                line,
                file: file_str.clone(),
            });
        }

        // --- Collect no-parens pipe calls: |> function_name (arity 1) ---
        // e.g. `"test" |> validate` — the piped value is the sole argument.
        // Skip if the name is immediately followed by `(` or `.` — those are
        // handled by pipe_call_re and pipe_remote_call_re respectively.
        for cap in self.pipe_call_no_parens_re.captures_iter(&source) {
            let name = cap.get(1).unwrap().as_str();
            if ELIXIR_KEYWORDS.contains(&name) {
                continue;
            }
            // Group 2 is the first non-space char after the name (if any).
            // Skip if it is `(` or `.` to avoid double-counting.
            let trailing = cap.get(2).map_or("", |m| m.as_str());
            if trailing == "(" || trailing == "." {
                continue;
            }
            let byte = cap.get(0).unwrap().start();
            let line = Self::byte_to_line(&line_starts, byte);

            calls.push(FunctionCall {
                name: name.to_string(),
                arity: Some(1),
                line,
                file: file_str.clone(),
            });
        }

        // --- Collect pipe-into-remote calls: |> Some.Module.fn(args) (arity += 1) ---
        for cap in self.pipe_remote_call_re.captures_iter(&source) {
            let name = cap.get(1).unwrap().as_str();
            if ELIXIR_KEYWORDS.contains(&name) {
                continue;
            }
            let open_paren = cap.get(0).unwrap().end() - 1;
            let byte = cap.get(0).unwrap().start();
            let args_str = Self::extract_args(&source, open_paren).unwrap_or("");
            let explicit_args = Self::count_args(args_str);
            let arity = if args_str.trim().is_empty() {
                1
            } else {
                explicit_args + 1
            };
            let line = Self::byte_to_line(&line_starts, byte);

            calls.push(FunctionCall {
                name: name.to_string(),
                arity: Some(arity),
                line,
                file: file_str.clone(),
            });
        }

        // --- Collect function captures: &Module.fn/arity or &local_fn/arity ---
        for cap in self.capture_re.captures_iter(&source) {
            let name = cap.get(1).unwrap().as_str();
            if ELIXIR_KEYWORDS.contains(&name) {
                continue;
            }
            let arity: usize = cap.get(2).unwrap().as_str().parse().unwrap_or(0);
            let byte = cap.get(0).unwrap().start();
            let line = Self::byte_to_line(&line_starts, byte);

            calls.push(FunctionCall {
                name: name.to_string(),
                arity: Some(arity),
                line,
                file: file_str.clone(),
            });
        }

        // --- Collect apply/3 and Kernel.apply/3 call sites ---
        // `apply(module, :fn_name, [a, b])` calls `module.fn_name/2` at runtime.
        // When the args are a literal list, arity = list length.
        // When the args are a variable or expression, arity is unknown (None),
        // which the cross-reference pass treats as matching any arity.
        for cap in self.apply_re.captures_iter(&source) {
            let name = cap.get(1).unwrap().as_str();
            if ELIXIR_KEYWORDS.contains(&name) {
                continue;
            }
            let arity = cap.get(2).map(|m| Self::count_args(m.as_str()));
            let byte = cap.get(0).unwrap().start();
            let line = Self::byte_to_line(&line_starts, byte);

            calls.push(FunctionCall {
                name: name.to_string(),
                arity,
                line,
                file: file_str.clone(),
            });
        }
        // When Elixir compiles `def foo(a, opts \\ [])`, it generates a hidden
        // foo/1 clause that calls foo/2 with the default filled in.  So any
        // observed call to foo/1 (or foo/0, etc.) implicitly calls the full-arity
        // body too.  We emit a phantom call to the max-arity variant for every
        // lower-arity call we actually saw, so the full-arity body is never
        // flagged as unused.
        let delegations: Vec<FunctionCall> = calls
            .iter()
            .filter_map(|c| {
                let called_arity = c.arity?;
                default_ranges
                    .iter()
                    .find(|(name, max_arity, min_arity)| {
                        name == &c.name && called_arity < *max_arity && called_arity >= *min_arity
                    })
                    .map(|(name, max_arity, _)| FunctionCall {
                        name: name.clone(),
                        arity: Some(*max_arity),
                        line: 0, // synthetic
                        file: file_str.clone(),
                    })
            })
            .collect();
        calls.extend(delegations);

        Ok(FileAnalysis { definitions, calls })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    fn analyzer() -> ElixirAnalyzer {
        ElixirAnalyzer::new()
    }

    /// Write `source` to a temp `.ex` file and run the analyzer on it.
    fn analyze_source(source: &str) -> FileAnalysis {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().with_extension("ex");
        std::fs::write(&path, source).unwrap();
        analyzer().analyze_file(&path).unwrap()
    }

    /// Return true if a definition with this name and arity was found.
    fn has_def(analysis: &FileAnalysis, name: &str, arity: usize) -> bool {
        analysis
            .definitions
            .iter()
            .any(|d| d.name == name && d.arity == Some(arity))
    }

    /// Return true if a call with this name and arity was found.
    fn has_call(analysis: &FileAnalysis, name: &str, arity: usize) -> bool {
        analysis
            .calls
            .iter()
            .any(|c| c.name == name && c.arity == Some(arity))
    }

    // -------------------------------------------------------------------------
    // count_args unit tests
    // -------------------------------------------------------------------------

    #[test]
    fn count_args_empty_string() {
        assert_eq!(ElixirAnalyzer::count_args(""), 0);
    }

    #[test]
    fn count_args_whitespace_only() {
        assert_eq!(ElixirAnalyzer::count_args("   "), 0);
    }

    #[test]
    fn count_args_single_arg() {
        assert_eq!(ElixirAnalyzer::count_args("x"), 1);
    }

    #[test]
    fn count_args_two_args() {
        assert_eq!(ElixirAnalyzer::count_args("x, y"), 2);
    }

    #[test]
    fn count_args_three_args() {
        assert_eq!(ElixirAnalyzer::count_args("a, b, c"), 3);
    }

    #[test]
    fn count_args_nested_tuple() {
        // {a, b} is one argument despite the inner comma
        assert_eq!(ElixirAnalyzer::count_args("{a, b}, c"), 2);
    }

    #[test]
    fn count_args_nested_list() {
        assert_eq!(ElixirAnalyzer::count_args("[1, 2, 3], opts"), 2);
    }

    #[test]
    fn count_args_nested_parens() {
        // foo(bar(x, y), z) → 2 top-level args
        assert_eq!(ElixirAnalyzer::count_args("bar(x, y), z"), 2);
    }

    #[test]
    fn count_args_deeply_nested() {
        assert_eq!(ElixirAnalyzer::count_args("{[{a, b}]}, c, d"), 3);
    }

    #[test]
    fn count_args_underscore() {
        // `_` is a valid argument and must count as arity 1
        assert_eq!(ElixirAnalyzer::count_args("_"), 1);
    }

    #[test]
    fn count_args_underscore_prefixed() {
        // `_scope`, `_opts` etc. are named ignored args — still count
        assert_eq!(ElixirAnalyzer::count_args("_version, _scope"), 2);
    }

    #[test]
    fn count_args_underscore_with_tuple_pattern() {
        // `def foo(_, {file, _scope})` — two args, inner comma ignored
        assert_eq!(ElixirAnalyzer::count_args("_, {file, _scope}"), 2);
    }

    #[test]
    fn count_args_all_underscores() {
        assert_eq!(ElixirAnalyzer::count_args("_, _, _"), 3);
    }

    // -------------------------------------------------------------------------
    // count_defaults unit tests
    // -------------------------------------------------------------------------

    #[test]
    fn count_defaults_none() {
        assert_eq!(ElixirAnalyzer::count_defaults("a, b, c"), 0);
    }

    #[test]
    fn count_defaults_empty() {
        assert_eq!(ElixirAnalyzer::count_defaults(""), 0);
    }

    #[test]
    fn count_defaults_single() {
        assert_eq!(ElixirAnalyzer::count_defaults(r"opts \\ []"), 1);
    }

    #[test]
    fn count_defaults_two() {
        assert_eq!(ElixirAnalyzer::count_defaults(r"a, b \\ true, c \\ nil"), 2);
    }

    #[test]
    fn count_defaults_all_args_defaulted() {
        assert_eq!(ElixirAnalyzer::count_defaults(r"a \\ 1, b \\ 2"), 2);
    }

    #[test]
    fn count_defaults_nested_default_value_not_double_counted() {
        // The default value itself contains a backslash-like sequence inside a
        // nested structure — depth guard should prevent double-counting.
        assert_eq!(ElixirAnalyzer::count_defaults(r"a, opts \\ [key: 1]"), 1);
    }

    #[test]
    fn count_defaults_two_list_defaults() {
        // `params \\ [], opts \\ []` — two separate defaults, each with a list value.
        assert_eq!(
            ElixirAnalyzer::count_defaults(r"params \\ [], opts \\ []"),
            2
        );
    }

    #[test]
    fn count_args_two_list_defaulted_params() {
        // The comma between `params \\ []` and `opts \\ []` is at depth 0
        // after `]` closes — must be counted as a top-level separator.
        assert_eq!(ElixirAnalyzer::count_args(r"params \\ [], opts \\ []"), 2);
    }

    // -------------------------------------------------------------------------
    // Default-arg definition detection
    // -------------------------------------------------------------------------

    #[test]
    fn def_with_one_default_registers_both_arities() {
        // `def foo(a, b \\ true)` must register as both foo/1 and foo/2
        let src = r"def foo(a, b \\ true), do: {a, b}";
        let analysis = analyze_source(src);
        assert!(
            has_def(&analysis, "foo", 1),
            "expected foo/1 (omitting default)"
        );
        assert!(
            has_def(&analysis, "foo", 2),
            "expected foo/2 (providing default)"
        );
    }

    #[test]
    fn def_with_two_defaults_registers_all_three_arities() {
        let src = r"def connect(host, port \\ 80, tls \\ false), do: {host, port, tls}";
        let analysis = analyze_source(src);
        assert!(has_def(&analysis, "connect", 1));
        assert!(has_def(&analysis, "connect", 2));
        assert!(has_def(&analysis, "connect", 3));
    }

    #[test]
    fn def_with_two_list_defaults_registers_all_arities() {
        // `def foo!(params \\ [], opts \\ []) do` — both defaults are list values.
        // Must register foo!/0, foo!/1, foo!/2.
        let src = r#"
def foo!(params \\ [], opts \\ []) do
  {params, opts}
end
"#;
        let analysis = analyze_source(src);
        assert!(has_def(&analysis, "foo!", 0), "foo!/0 missing");
        assert!(has_def(&analysis, "foo!", 1), "foo!/1 missing");
        assert!(has_def(&analysis, "foo!", 2), "foo!/2 missing");
    }

    #[test]
    fn calling_foo_bang_zero_arity_marks_full_body_as_used() {
        let src = r#"
defmodule MyApp do
  def foo!(params \\ [], opts \\ []) do
    {params, opts}
  end

  def run() do
    foo!()
  end
end
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "foo!", 0));
        assert!(
            has_call(&analysis, "foo!", 2),
            "foo!/2 body must be marked used via delegation"
        );
    }

    #[test]
    fn multi_default_all_arities_marked_used_without_any_call() {
        // With two defaults, the compiler generates foo!/0 and foo!/1 as hidden
        // delegating clauses.  None of foo!/0, foo!/1, foo!/2 require an explicit
        // call site — they are all considered used by the compiler machinery alone.
        let src = r#"
defmodule MyApp do
  def foo!(params \\ [], opts \\ []) do
    {params, opts}
  end
end
"#;
        let analysis = analyze_source(src);
        assert!(
            has_call(&analysis, "foo!", 0),
            "foo!/0 must be implicitly used"
        );
        assert!(
            has_call(&analysis, "foo!", 1),
            "foo!/1 must be implicitly used"
        );
        assert!(
            has_call(&analysis, "foo!", 2),
            "foo!/2 must be implicitly used"
        );
    }

    #[test]
    fn def_with_all_defaults_registers_zero_through_n() {
        let src = r"def greet(name \\ :world, loud \\ false), do: {name, loud}";
        let analysis = analyze_source(src);
        assert!(has_def(&analysis, "greet", 0));
        assert!(has_def(&analysis, "greet", 1));
        assert!(has_def(&analysis, "greet", 2));
    }

    #[test]
    fn def_without_defaults_unchanged() {
        // Sanity: non-defaulted functions still register only one arity.
        let src = "def add(a, b), do: a + b";
        let analysis = analyze_source(src);
        assert!(has_def(&analysis, "add", 2));
        assert!(!has_def(&analysis, "add", 1));
        assert!(!has_def(&analysis, "add", 0));
    }

    #[test]
    fn call_with_omitted_default_matches_definition() {
        // foo/2 defined with one default; calling as foo(1) must not be flagged unused.
        let src = r#"
def run() do
  foo(1)
end
def foo(a, b \\ true), do: {a, b}
"#;
        let analysis = analyze_source(src);
        // The call foo(1) has arity 1; foo is defined for arity 1 via the default.
        assert!(has_call(&analysis, "foo", 1));
        assert!(has_def(&analysis, "foo", 1));
    }

    #[test]
    fn call_with_all_args_still_matches_defaulted_definition() {
        let src = r#"
def run() do
  foo(1, false)
end
def foo(a, b \\ true), do: {a, b}
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "foo", 2));
        assert!(has_def(&analysis, "foo", 2));
    }

    #[test]
    fn private_def_with_default_also_expands_arities() {
        let src = r"defp helper(x, opts \\ []), do: {x, opts}";
        let analysis = analyze_source(src);
        assert!(has_def(&analysis, "helper", 1));
        assert!(has_def(&analysis, "helper", 2));
        let d = analysis
            .definitions
            .iter()
            .find(|d| d.name == "helper" && d.arity == Some(1))
            .unwrap();
        assert!(d.is_private);
    }

    // -------------------------------------------------------------------------
    // Default-arg implicit delegation (split header + body form)
    // -------------------------------------------------------------------------

    #[test]
    fn body_clause_not_flagged_unused_when_only_header_has_default() {
        // The split-clause form:
        //   def view_dispatch(opts \\ [])       ← header, generates /0 → /1
        //   def view_dispatch(_opts) do ... end ← body at /1
        // view_dispatch/1 must NOT be flagged unused just because no source
        // line explicitly calls view_dispatch/1 — the compiler-generated /0
        // always delegates to it.
        let src = r#"
defmodule MyApp do
  def view_dispatch(opts \\ [])

  def view_dispatch(_opts) do
    :ok
  end
end
"#;
        let analysis = analyze_source(src);
        assert!(
            has_def(&analysis, "view_dispatch", 1),
            "view_dispatch/1 must be defined"
        );
        assert!(
            has_call(&analysis, "view_dispatch", 1),
            "view_dispatch/1 must be marked as implicitly called"
        );
    }

    #[test]
    fn header_clause_with_multiple_defaults_all_bodies_marked_used() {
        let src = r#"
defmodule MyApp do
  def connect(host, port \\ 80, tls \\ false)

  def connect(host, port, tls) do
    {host, port, tls}
  end
end
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "connect", 3));
    }

    #[test]
    fn calling_default_arity_also_marks_full_arity_as_used() {
        // The canonical split-clause form:
        //   def foo(opts \\ [])          ← header clause (no body)
        //   def foo(opts) do ... end     ← body clause
        // Calling foo/0 must mark both foo/0 and foo/1 as used, because the
        // compiler generates a hidden foo/0 that delegates to foo/1.
        let src = r#"
defmodule MyApp do
  def foo(opts \\ [])

  def foo(opts) do
    opts
  end

  def run() do
    foo()
  end
end
"#;
        let analysis = analyze_source(src);
        assert!(
            has_call(&analysis, "foo", 0),
            "foo/0 must be recorded as called"
        );
        assert!(
            has_call(&analysis, "foo", 1),
            "foo/1 must be implicitly called via delegation"
        );
    }

    #[test]
    fn calling_intermediate_arity_delegates_to_full_arity() {
        // def connect(host, port \\ 80, tls \\ false)
        // Calling connect/1 must also mark connect/3 as used.
        let src = r#"
defmodule MyApp do
  def connect(host, port \\ 80, tls \\ false)

  def connect(host, port, tls) do
    {host, port, tls}
  end

  def run() do
    connect("localhost")
  end
end
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "connect", 1));
        assert!(
            has_call(&analysis, "connect", 3),
            "connect/3 body must be marked used via delegation"
        );
    }

    #[test]
    fn calling_full_arity_does_not_add_spurious_delegation() {
        // When the caller passes all args explicitly, the delegation pass adds
        // nothing extra beyond what the definition-time synthesis already covers.
        // All arities in the default range are always marked used by the compiler-
        // generated delegating clauses, so foo/0 and foo/1 are both considered
        // used regardless of what the caller passes.
        let src = r#"
defmodule MyApp do
  def foo(opts \\ [])

  def foo(opts) do
    opts
  end

  def run() do
    foo([key: :value])
  end
end
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "foo", 1));
        // foo/0 is a compiler-generated delegator — it is always implicitly called.
        assert!(has_call(&analysis, "foo", 0));
    }

    #[test]
    fn delegation_does_not_fire_for_unrelated_function_same_name() {
        // Two unrelated functions named `init` in different modules in the same
        // file — delegation for one must not bleed into the other.
        let src = r#"
defmodule A do
  def init(state \\ %{})

  def init(state) do
    state
  end
end

defmodule B do
  def run() do
    A.init()
  end
end
"#;
        let analysis = analyze_source(src);
        // init/1 should be marked used via delegation from the init/0 call.
        assert!(has_call(&analysis, "init", 1));
    }

    #[test]
    fn detects_zero_arity_public_def() {
        let src = "def hello(), do: :ok";
        assert!(has_def(&analyze_source(src), "hello", 0));
    }

    #[test]
    fn detects_one_arity_public_def() {
        let src = "def greet(name), do: IO.puts(name)";
        assert!(has_def(&analyze_source(src), "greet", 1));
    }

    #[test]
    fn detects_two_arity_public_def() {
        let src = "def add(a, b), do: a + b";
        assert!(has_def(&analyze_source(src), "add", 2));
    }

    #[test]
    fn detects_private_def() {
        let src = "defp secret(x), do: x * 2";
        let analysis = analyze_source(src);
        let def = analysis
            .definitions
            .iter()
            .find(|d| d.name == "secret")
            .unwrap();
        assert!(def.is_private);
        assert_eq!(def.arity, Some(1));
    }

    #[test]
    fn public_def_is_not_private() {
        let src = "def visible(x), do: x";
        let analysis = analyze_source(src);
        let def = analysis
            .definitions
            .iter()
            .find(|d| d.name == "visible")
            .unwrap();
        assert!(!def.is_private);
    }

    #[test]
    fn detects_multiline_def_body() {
        let src = r#"
def process(input) do
  input
  |> String.trim()
end
"#;
        assert!(has_def(&analyze_source(src), "process", 1));
    }

    #[test]
    fn detects_multiple_defs_in_file() {
        let src = r#"
def foo(a), do: a
def bar(a, b), do: a + b
defp baz(a, b, c), do: a + b + c
"#;
        let analysis = analyze_source(src);
        assert!(has_def(&analysis, "foo", 1));
        assert!(has_def(&analysis, "bar", 2));
        assert!(has_def(&analysis, "baz", 3));
    }

    #[test]
    fn detects_def_with_when_guard() {
        let src = "def double(x) when is_integer(x), do: x * 2";
        assert!(has_def(&analyze_source(src), "double", 1));
    }

    #[test]
    fn underscore_arg_counts_toward_arity() {
        // `def foo(_, opts)` — `_` is an arg, arity must be 2
        let src = "def foo(_, opts), do: opts";
        assert!(has_def(&analyze_source(src), "foo", 2));
    }

    #[test]
    fn underscore_prefixed_arg_counts_toward_arity() {
        // `def s3_object_headers(_version, {file, _scope})` — arity 2
        let src = "def s3_object_headers(_version, {file, _scope}), do: []";
        assert!(has_def(&analyze_source(src), "s3_object_headers", 2));
    }

    #[test]
    fn all_underscore_args_counted() {
        let src = "def noop(_, _, _), do: :ok";
        assert!(has_def(&analyze_source(src), "noop", 3));
    }

    #[test]
    fn underscore_arg_with_default_counts_correctly() {
        // `def foo(_ \\ nil)` — arity 1, 1 default → also registers foo/0
        let src = r"def foo(_ \\ nil), do: :ok";
        let analysis = analyze_source(src);
        assert!(has_def(&analysis, "foo", 0));
        assert!(has_def(&analysis, "foo", 1));
    }

    #[test]
    fn detects_zero_arity_shorthand_def() {
        // `def name, do: ...` — no parens, zero args
        let src = "def init, do: :ok";
        assert!(has_def(&analyze_source(src), "init", 0));
    }

    #[test]
    fn detects_def_with_pattern_match_args() {
        // Pattern matched args still count by commas
        let src = "def handle({:ok, val}, opts), do: val";
        assert!(has_def(&analyze_source(src), "handle", 2));
    }

    #[test]
    fn detects_bang_function() {
        let src = "def fetch!(id), do: id";
        assert!(has_def(&analyze_source(src), "fetch!", 1));
    }

    #[test]
    fn detects_question_mark_function() {
        let src = "def valid?(attrs), do: true";
        assert!(has_def(&analyze_source(src), "valid?", 1));
    }

    #[test]
    fn records_correct_line_number_for_def() {
        let src = "\n\ndef on_line_three(x), do: x\n";
        let analysis = analyze_source(src);
        let def = analysis
            .definitions
            .iter()
            .find(|d| d.name == "on_line_three" && d.arity == Some(1))
            .unwrap();
        assert_eq!(def.line, 3);
    }

    // -------------------------------------------------------------------------
    // Call site detection
    // -------------------------------------------------------------------------

    #[test]
    fn detects_simple_local_call() {
        let src = r#"
def run() do
  helper(1)
end
defp helper(x), do: x
"#;
        assert!(has_call(&analyze_source(src), "helper", 1));
    }

    #[test]
    fn detects_call_with_multiple_args() {
        let src = r#"
def run() do
  combine(1, 2, 3)
end
"#;
        assert!(has_call(&analyze_source(src), "combine", 3));
    }

    #[test]
    fn does_not_emit_call_for_elixir_keywords() {
        let src = r#"
def run(x) do
  if(x, do: :yes, else: :no)
end
"#;
        let analysis = analyze_source(src);
        assert!(!analysis.calls.iter().any(|c| c.name == "if"));
    }

    #[test]
    fn does_not_emit_call_for_def_keyword() {
        let src = "def foo(x), do: x";
        let analysis = analyze_source(src);
        assert!(!analysis.calls.iter().any(|c| c.name == "def"));
        assert!(!analysis.calls.iter().any(|c| c.name == "defp"));
    }

    #[test]
    fn detects_zero_arg_call() {
        let src = r#"
def run() do
  init()
end
"#;
        assert!(has_call(&analyze_source(src), "init", 0));
    }

    // -------------------------------------------------------------------------
    // Pipe call detection
    // -------------------------------------------------------------------------

    #[test]
    fn detects_pipe_call_zero_explicit_args() {
        // `x |> transform()` → arity 1 (piped value only)
        let src = r#"
def run(x) do
  x |> transform()
end
defp transform(v), do: v
"#;
        assert!(has_call(&analyze_source(src), "transform", 1));
    }

    #[test]
    fn detects_pipe_call_one_explicit_arg() {
        // `x |> transform(1)` → arity 2
        let src = r#"
def run(x) do
  x |> transform(1)
end
defp transform(a, b), do: a + b
"#;
        assert!(has_call(&analyze_source(src), "transform", 2));
    }

    #[test]
    fn detects_chained_pipe_calls() {
        let src = r#"
def run(x) do
  x |> step_one() |> step_two()
end
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "step_one", 1));
        assert!(has_call(&analysis, "step_two", 1));
    }

    #[test]
    fn detects_pipe_into_two_arg_function() {
        let src = r#"
def run(list) do
  list |> Enum.map(fn x -> x end)
end
"#;
        // map gets piped value + fn arg = arity 2
        assert!(has_call(&analyze_source(src), "map", 2));
    }

    #[test]
    fn detects_pipe_call_no_parens() {
        // `"test" |> validate` — validate/1 called with the piped value
        let src = r#"
def foo() do
  "test"
  |> validate
end

def validate(foo) do
  foo
end
"#;
        assert!(has_call(&analyze_source(src), "validate", 1));
    }

    #[test]
    fn detects_chained_pipe_no_parens() {
        let src = r#"
def run(x) do
  x
  |> trim
  |> downcase
end
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "trim", 1));
        assert!(has_call(&analysis, "downcase", 1));
    }

    #[test]
    fn pipe_no_parens_does_not_double_count_when_parens_present() {
        // `|> validate(opts)` — handled by pipe_call_re giving arity 2.
        // The no-parens pass must not additionally emit validate/1 from the pipe itself.
        // (call_re will independently see validate(opts) as validate/1 — that's correct
        // and unrelated to the pipe pass.)
        let src = r#"
def run(x, opts) do
  x |> validate(opts)
end
def validate(x, opts), do: {x, opts}
"#;
        let analysis = analyze_source(src);
        // Pipe gives validate/2
        assert!(has_call(&analysis, "validate", 2));
        // Verify the no-parens pass didn't fire by checking there's no pipe-sourced
        // validate/1 — we do this by counting: call_re sees validate(opts) as /1,
        // but the pipe no-parens pass must not add another one.
        // The count of validate/1 calls should be exactly 1 (from call_re), not 2.
        let validate_1_count = analysis
            .calls
            .iter()
            .filter(|c| c.name == "validate" && c.arity == Some(1))
            .count();
        assert!(
            validate_1_count <= 1,
            "pipe no-parens pass must not double-emit validate/1"
        );
    }

    #[test]
    fn pipe_no_parens_does_not_match_remote_call() {
        // `|> Enum.map` — remote, handled by pipe_remote_call_re, not no-parens pass
        // (no-parens pass only matches lowercase-starting names anyway)
        let src = r#"
def run(list) do
  list |> Enum.map(&String.upcase/1)
end
"#;
        let analysis = analyze_source(src);
        // `map` should appear from remote pass, not generate a spurious lowercase match
        // The no-parens regex won't fire on `Enum.map` since `Enum` starts uppercase
        assert!(!analysis.calls.iter().any(|c| c.name == "enum"));
    }

    // -------------------------------------------------------------------------
    // Arity disambiguation
    // -------------------------------------------------------------------------

    #[test]
    fn same_name_different_arity_both_detected_as_defs() {
        let src = r#"
def greet(), do: "hi"
def greet(name), do: "hi #{name}"
"#;
        let analysis = analyze_source(src);
        assert!(has_def(&analysis, "greet", 0));
        assert!(has_def(&analysis, "greet", 1));
    }

    #[test]
    fn same_name_different_arity_both_detected_as_calls() {
        let src = r#"
def run() do
  greet()
  greet("world")
end
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "greet", 0));
        assert!(has_call(&analysis, "greet", 1));
    }

    // -------------------------------------------------------------------------
    // canonical_key
    // -------------------------------------------------------------------------

    #[test]
    fn canonical_key_includes_arity() {
        let src = "def foo(a, b), do: a + b";
        let analysis = analyze_source(src);
        let def = analysis
            .definitions
            .iter()
            .find(|d| d.name == "foo")
            .unwrap();
        assert_eq!(def.canonical_key(), "foo/2");
    }

    #[test]
    fn canonical_key_zero_arity() {
        let src = "def init(), do: :ok";
        let analysis = analyze_source(src);
        let def = analysis
            .definitions
            .iter()
            .find(|d| d.name == "init")
            .unwrap();
        assert_eq!(def.canonical_key(), "init/0");
    }

    // -------------------------------------------------------------------------
    // File extension support
    // -------------------------------------------------------------------------

    #[test]
    fn supports_ex_extension() {
        let a = analyzer();
        let p = std::path::Path::new("foo.ex");
        assert!(a.supports_file(p));
    }

    #[test]
    fn supports_exs_extension() {
        let a = analyzer();
        let p = std::path::Path::new("foo.exs");
        assert!(a.supports_file(p));
    }

    #[test]
    fn does_not_support_rb_extension() {
        let a = analyzer();
        let p = std::path::Path::new("foo.rb");
        assert!(!a.supports_file(p));
    }

    #[test]
    fn name_is_elixir() {
        assert_eq!(analyzer().name(), "Elixir");
    }

    // -------------------------------------------------------------------------
    // Full-module integration: unused detection end-to-end
    // -------------------------------------------------------------------------

    #[test]
    fn unused_public_function_is_flagged() {
        let src = r#"
defmodule MyApp do
  def used(x), do: x
  def unused_fn(x), do: x * 2

  def run() do
    used(1)
  end
end
"#;
        let analysis = analyze_source(src);
        // `unused_fn` must be in definitions
        assert!(has_def(&analysis, "unused_fn", 1));
        // `unused_fn` must NOT appear as a call
        assert!(!has_call(&analysis, "unused_fn", 1));
    }

    #[test]
    fn called_function_is_not_flagged_as_unused() {
        let src = r#"
defmodule MyApp do
  def run(x) do
    helper(x)
  end

  defp helper(x), do: x + 1
end
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "helper", 1));
    }

    #[test]
    fn pipeline_caller_marks_function_as_used() {
        let src = r#"
defmodule MyApp do
  def run(x) do
    x |> normalize()
  end

  defp normalize(v), do: String.downcase(v)
end
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "normalize", 1));
    }

    #[test]
    fn empty_file_produces_no_definitions_or_calls() {
        let analysis = analyze_source("");
        assert!(analysis.definitions.is_empty());
        assert!(analysis.calls.is_empty());
    }

    #[test]
    fn comments_do_not_produce_spurious_definitions() {
        // A `#` comment containing `def` should not be picked up
        let src = r#"
# def fake_fn(x), do: x
defmodule Real do
  def real_fn(x), do: x
end
"#;
        let analysis = analyze_source(src);
        assert!(!analysis.definitions.iter().any(|d| d.name == "fake_fn"));
        assert!(has_def(&analysis, "real_fn", 1));
    }

    // -------------------------------------------------------------------------
    // Remote calls: Module.function(args)
    // -------------------------------------------------------------------------

    #[test]
    fn detects_simple_remote_call() {
        let src = r#"
def run() do
  Repo.all(User)
end
"#;
        assert!(has_call(&analyze_source(src), "all", 1));
    }

    #[test]
    fn detects_nested_module_remote_call() {
        let src = r#"
def run() do
  Mutations.Send.send(payload, opts)
end
"#;
        assert!(has_call(&analyze_source(src), "send", 2));
    }

    #[test]
    fn detects_remote_call_zero_args() {
        let src = r#"
def run() do
  MyApp.Repo.start_link()
end
"#;
        assert!(has_call(&analyze_source(src), "start_link", 0));
    }

    #[test]
    fn detects_remote_call_piped() {
        // `x |> Some.Module.transform(y)` — pipe_call_re won't catch this,
        // but remote_call_re will still see `transform(y)` with arity 1.
        // The piped arg is NOT added here — only bare remote_call_re fires.
        let src = r#"
def run(x) do
  x |> Transformer.Core.transform(extra)
end
"#;
        assert!(has_call(&analyze_source(src), "transform", 1));
    }

    // -------------------------------------------------------------------------
    // Function captures: &Module.function/arity and &local_fn/arity
    // -------------------------------------------------------------------------

    #[test]
    fn detects_local_capture() {
        let src = r#"
def run(list) do
  Enum.map(list, &my_helper/1)
end
defp my_helper(x), do: x * 2
"#;
        assert!(has_call(&analyze_source(src), "my_helper", 1));
    }

    #[test]
    fn detects_remote_capture_single_module() {
        let src = r#"
def run(list) do
  Enum.map(list, &Formatter.format/1)
end
"#;
        assert!(has_call(&analyze_source(src), "format", 1));
    }

    #[test]
    fn detects_remote_capture_nested_module() {
        // The exact case from the bug report: `&Mutations.Send.send/2`
        let src = r#"
def dispatch(events) do
  Enum.each(events, &Mutations.Send.send/2)
end
"#;
        assert!(has_call(&analyze_source(src), "send", 2));
    }

    #[test]
    fn detects_capture_zero_arity() {
        let src = r#"
def run() do
  Task.start(&init/0)
end
def init(), do: :ok
"#;
        assert!(has_call(&analyze_source(src), "init", 0));
    }

    #[test]
    fn detects_capture_high_arity() {
        let src = r#"
def run() do
  apply(&process/4, args)
end
"#;
        assert!(has_call(&analyze_source(src), "process", 4));
    }

    #[test]
    fn capture_marks_function_as_used_in_cross_reference() {
        // If a function is only referenced via capture, it should NOT be flagged unused
        let src = r#"
defmodule MyApp do
  def run(list) do
    Enum.map(list, &helper/1)
  end

  defp helper(x), do: x + 1
end
"#;
        let analysis = analyze_source(src);
        // helper/1 is captured, so it should appear as a call
        assert!(has_call(&analysis, "helper", 1));
    }

    // -------------------------------------------------------------------------
    // OTP behaviour callbacks
    // -------------------------------------------------------------------------

    #[test]
    fn application_start_is_not_unused() {
        let src = r#"
defmodule MyApp.Application do
  use Application

  def start(_type, _args) do
    children = []
    Supervisor.start_link(children, strategy: :one_for_one)
  end
end
"#;
        let analysis = analyze_source(src);
        // start/2 is a behaviour callback — must appear as a call
        assert!(has_call(&analysis, "start", 2));
    }

    #[test]
    fn application_stop_callback_is_not_unused() {
        let src = r#"
defmodule MyApp.Application do
  use Application

  def start(_type, _args), do: {:ok, self()}
  def stop(_state), do: :ok
end
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "stop", 1));
    }

    #[test]
    fn genserver_callbacks_are_not_unused() {
        let src = r#"
defmodule MyWorker do
  use GenServer

  def init(state), do: {:ok, state}
  def handle_call(:ping, _from, state), do: {:reply, :pong, state}
  def handle_cast(:noop, state), do: {:noreply, state}
  def handle_info(:tick, state), do: {:noreply, state}
  def terminate(_reason, _state), do: :ok
end
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "init", 1));
        assert!(has_call(&analysis, "handle_call", 3));
        assert!(has_call(&analysis, "handle_cast", 2));
        assert!(has_call(&analysis, "handle_info", 2));
        assert!(has_call(&analysis, "terminate", 2));
    }

    #[test]
    fn supervisor_init_callback_is_not_unused() {
        let src = r#"
defmodule MyApp.Supervisor do
  use Supervisor

  def init(_arg) do
    children = []
    Supervisor.init(children, strategy: :one_for_one)
  end
end
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "init", 1));
    }

    #[test]
    fn behaviour_callback_only_synthesized_when_defined() {
        // stop/1 is a known Application callback but is NOT defined here —
        // no synthetic call should be emitted for it.
        let src = r#"
defmodule MyApp.Application do
  use Application

  def start(_type, _args), do: {:ok, self()}
end
"#;
        let analysis = analyze_source(src);
        assert!(!has_call(&analysis, "stop", 1));
    }

    #[test]
    fn behaviour_via_at_behaviour_attribute() {
        // `@behaviour GenServer` (explicit attribute form) should work too.
        let src = r#"
defmodule MyWorker do
  @behaviour GenServer

  def init(state), do: {:ok, state}
  def handle_call(msg, _from, state), do: {:reply, msg, state}
end
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "init", 1));
        assert!(has_call(&analysis, "handle_call", 3));
    }

    // -------------------------------------------------------------------------
    // Phoenix router: action atoms and `as:` helpers
    // -------------------------------------------------------------------------

    #[test]
    fn router_action_atom_is_synthesized_as_call() {
        // `get "/current", CurrentController, :current` means Phoenix will
        // dispatch to CurrentController.current/2 — so `current` must appear
        // as a call with arity 2.
        let src = r#"
defmodule MyAppWeb.Router do
  use Phoenix.Router

  get "/current", CurrentController, :current
end
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "current", 2));
    }

    #[test]
    fn router_action_atom_with_as_option_is_synthesized() {
        // The `as:` option does not affect which action is called.
        let src = r#"
defmodule MyAppWeb.Router do
  use Phoenix.Router

  get "/current", CurrentController, :current, as: :current
end
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "current", 2));
    }

    #[test]
    fn router_as_generates_path_and_url_helper_definitions() {
        // `as: :current` must produce synthetic definitions for:
        //   current_path/2, current_path/3, current_url/2, current_url/3
        let src = r#"
defmodule MyAppWeb.Router do
  use Phoenix.Router

  get "/current", CurrentController, :current, as: :current
end
"#;
        let analysis = analyze_source(src);
        assert!(has_def(&analysis, "current_path", 2));
        assert!(has_def(&analysis, "current_path", 3));
        assert!(has_def(&analysis, "current_url", 2));
        assert!(has_def(&analysis, "current_url", 3));
    }

    #[test]
    fn router_as_alias_differs_from_action_name() {
        // When the alias name differs from the action, each must be handled
        // independently: action atom → call, alias → helper definitions.
        let src = r#"
defmodule MyAppWeb.Router do
  use Phoenix.Router

  get "/session/new", SessionController, :new, as: :login
end
"#;
        let analysis = analyze_source(src);
        // Action :new → call new/2
        assert!(has_call(&analysis, "new", 2));
        // Alias :login → helper definitions
        assert!(has_def(&analysis, "login_path", 2));
        assert!(has_def(&analysis, "login_url", 2));
        // No spurious cross-contamination
        assert!(!has_def(&analysis, "new_path", 2));
        assert!(!has_call(&analysis, "login", 2));
    }

    #[test]
    fn router_multiple_verbs_all_produce_calls() {
        let src = r#"
defmodule MyAppWeb.Router do
  use Phoenix.Router

  get    "/users",     UserController, :index
  post   "/users",     UserController, :create
  delete "/users/:id", UserController, :delete
end
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "index", 2));
        assert!(has_call(&analysis, "create", 2));
        assert!(has_call(&analysis, "delete", 2));
    }

    #[test]
    fn router_route_without_as_produces_no_helper_defs() {
        // Without `as:`, no helper functions are generated.
        let src = r#"
defmodule MyAppWeb.Router do
  use Phoenix.Router

  get "/ping", PingController, :ping
end
"#;
        let analysis = analyze_source(src);
        assert!(!has_def(&analysis, "ping_path", 2));
        assert!(!has_def(&analysis, "ping_url", 2));
    }

    #[test]
    fn scope_with_as_prefixes_route_helpers() {
        // `scope ... as: :public` means route helpers inside are prefixed:
        //   `as: :current` inside → `public_current_path`, not `current_path`
        let src = r#"
defmodule MyAppWeb.Router do
  use Phoenix.Router

  scope "/api/public", V5ApiWeb.Public, as: :public do
    get "/current", CurrentController, :current, as: :current
  end
end
"#;
        let analysis = analyze_source(src);
        assert!(has_def(&analysis, "public_current_path", 2));
        assert!(has_def(&analysis, "public_current_path", 3));
        assert!(has_def(&analysis, "public_current_url", 2));
        assert!(has_def(&analysis, "public_current_url", 3));
        // The un-prefixed name must NOT be generated
        assert!(!has_def(&analysis, "current_path", 2));
        assert!(!has_def(&analysis, "current_url", 2));
    }

    #[test]
    fn scope_without_as_does_not_add_prefix() {
        // A scope with no `as:` is transparent for helper naming.
        let src = r#"
defmodule MyAppWeb.Router do
  use Phoenix.Router

  scope "/api" do
    get "/ping", PingController, :ping, as: :ping
  end
end
"#;
        let analysis = analyze_source(src);
        assert!(has_def(&analysis, "ping_path", 2));
        assert!(!has_def(&analysis, "_ping_path", 2));
    }

    #[test]
    fn nested_scopes_concatenate_prefixes() {
        // Nested scopes with `as:` chain their prefixes with `_`.
        let src = r#"
defmodule MyAppWeb.Router do
  use Phoenix.Router

  scope "/api", as: :api do
    scope "/v1", as: :v1 do
      get "/users", UserController, :index, as: :users
    end
  end
end
"#;
        let analysis = analyze_source(src);
        assert!(has_def(&analysis, "api_v1_users_path", 2));
        assert!(has_def(&analysis, "api_v1_users_url", 2));
        assert!(!has_def(&analysis, "users_path", 2));
    }

    #[test]
    fn scope_as_does_not_itself_produce_helper_defs() {
        // The scope line `as: :public` alone must not generate `public_path` —
        // only route lines with their own `as:` emit helpers.
        let src = r#"
defmodule MyAppWeb.Router do
  use Phoenix.Router

  scope "/api/public", V5ApiWeb.Public, as: :public do
    get "/current", CurrentController, :current
  end
end
"#;
        let analysis = analyze_source(src);
        // No route has its own `as:` so no helpers at all.
        assert!(!has_def(&analysis, "public_path", 2));
        assert!(!has_def(&analysis, "public_url", 2));
        // But the action is still reachable.
        assert!(has_call(&analysis, "current", 2));
    }

    #[test]
    fn scope_routes_action_atoms_always_synthesized_regardless_of_as() {
        // The `as:` option on a scope affects helper names only.
        // All action atoms in routes must still appear as calls.
        let src = r#"
defmodule MyAppWeb.Router do
  use Phoenix.Router

  scope "/api/public", V5ApiWeb.Public, as: :public do
    get "/current", CurrentController, :current, as: :current
    post "/session", SessionController, :create, as: :session
  end
end
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "current", 2));
        assert!(has_call(&analysis, "create", 2));
    }

    // -------------------------------------------------------------------------
    // use Module, :atom  — Phoenix macro-generator dispatch
    // -------------------------------------------------------------------------

    #[test]
    fn use_with_atom_synthesizes_call_to_zero_arity_fn() {
        // `use MyAppWeb, :view` must produce a synthetic call to `view/0`
        // so the definition in MyAppWeb is not flagged as unused.
        let src = r#"
defmodule MyAppWeb do
  def view() do
    quote do
      import MyAppWeb.HTML
    end
  end
end

defmodule MyWeb.PageView do
  use MyAppWeb, :view
end
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "view", 0));
    }

    #[test]
    fn use_with_atom_controller_synthesizes_call() {
        let src = r#"
defmodule MyAppWeb do
  def controller() do
    quote do
      use Phoenix.Controller
    end
  end
end

defmodule MyWeb.UserController do
  use MyAppWeb, :controller
end
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "controller", 0));
    }

    #[test]
    fn use_without_atom_does_not_synthesize_zero_arity_call() {
        // `use GenServer` has no atom — must not emit any zero-arity call named
        // after a fragment of the module name.
        let src = r#"
defmodule MyWorker do
  use GenServer
  def init(s), do: {:ok, s}
end
"#;
        let analysis = analyze_source(src);
        assert!(!analysis
            .calls
            .iter()
            .any(|c| c.arity == Some(0) && c.name == "genserver"));
    }

    #[test]
    fn multiple_use_atoms_each_synthesize_a_call() {
        let src = r#"
defmodule MyAppWeb do
  def view(), do: quote(do: :ok)
  def live_view(), do: quote(do: :ok)
end

defmodule A do
  use MyAppWeb, :view
end

defmodule B do
  use MyAppWeb, :live_view
end
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "view", 0));
        assert!(has_call(&analysis, "live_view", 0));
    }

    // -------------------------------------------------------------------------
    // apply/3 and Kernel.apply/3 dynamic dispatch
    // -------------------------------------------------------------------------

    #[test]
    fn apply_with_atom_and_args_list_emits_call() {
        let src = r#"
def run(module, opts) do
  apply(module, :authorize_url!, [opts])
end
def authorize_url!(opts), do: opts
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "authorize_url!", 1));
    }

    #[test]
    fn apply_zero_args_list_emits_zero_arity_call() {
        let src = r#"
def run(module) do
  apply(module, :reset, [])
end
def reset(), do: :ok
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "reset", 0));
    }

    #[test]
    fn apply_multiple_args_counts_list_elements_as_arity() {
        let src = r#"
def run(mod, a, b) do
  apply(mod, :process, [a, b])
end
def process(x, y), do: {x, y}
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "process", 2));
    }

    #[test]
    fn kernel_apply_also_detected() {
        let src = r#"
def run(mod) do
  Kernel.apply(mod, :fetch!, [1])
end
def fetch!(id), do: id
"#;
        let analysis = analyze_source(src);
        assert!(has_call(&analysis, "fetch!", 1));
    }

    #[test]
    fn apply_with_variable_args_emits_unknown_arity_call() {
        // `apply(mod, :fetch!, args)` — args is a variable, arity is unknown.
        // A FunctionCall with arity None must be emitted so the cross-reference
        // pass can match it against any definition of fetch!.
        let src = r#"
def run(mod, args) do
  apply(mod, :fetch!, args)
end
def fetch!(id), do: id
"#;
        let analysis = analyze_source(src);
        assert!(
            analysis
                .calls
                .iter()
                .any(|c| c.name == "fetch!" && c.arity.is_none()),
            "expected a fetch! call with unknown arity"
        );
    }

    #[test]
    fn apply_with_module_self_reference_and_variable_args() {
        // Variable atom — should not emit any call since :atom is required.
        let src = r#"
def dispatch(action, args) do
  apply(__MODULE__, action, args)
end
"#;
        let analysis = analyze_source(src);
        // `action` is not a :atom literal so no call should be recorded.
        assert!(!analysis.calls.iter().any(|c| c.name == "action"));
    }

    // -------------------------------------------------------------------------
    // dep_callbacks — scanning deps for defoverridable callbacks
    // -------------------------------------------------------------------------

    /// Write a fake dep file at `deps_path/lib/fake.ex` containing `source`,
    /// scan it, and return an analyzer with the resulting dep_callbacks table.
    fn analyzer_with_dep_source(dep_source: &str) -> ElixirAnalyzer {
        let dir = tempfile::tempdir().unwrap();
        let lib_dir = dir.path().join("lib");
        std::fs::create_dir_all(&lib_dir).unwrap();
        std::fs::write(lib_dir.join("fake.ex"), dep_source).unwrap();
        // Keep dir alive until after with_deps returns by moving it in.
        let analyzer = ElixirAnalyzer::new().with_deps(dir.path());
        drop(dir);
        analyzer
    }

    #[test]
    fn dep_scanning_finds_defoverridable_in_using_macro() {
        let dep_src = r#"
defmodule Waffle.Definition do
  defmacro __using__(_opts) do
    quote do
      defoverridable s3_object_headers: 2, acl: 2, validate: 1
    end
  end
end
"#;
        let analyzer = analyzer_with_dep_source(dep_src);
        assert!(
            analyzer.dep_callbacks.contains_key("Waffle.Definition"),
            "expected Waffle.Definition in dep_callbacks, got: {:?}",
            analyzer.dep_callbacks.keys().collect::<Vec<_>>()
        );
        let cbs = &analyzer.dep_callbacks["Waffle.Definition"];
        assert!(cbs.contains(&("s3_object_headers".to_string(), 2)));
        assert!(cbs.contains(&("acl".to_string(), 2)));
        assert!(cbs.contains(&("validate".to_string(), 1)));
    }

    #[test]
    fn dep_scanning_finds_defoverridable_multiline_in_before_compile() {
        // Waffle's actual pattern: multiline defoverridable inside __before_compile__
        let dep_src = r#"
defmodule Waffle.Definition.Storage do
  defmacro __before_compile__(_env) do
    quote do
      defoverridable storage_dir_prefix: 0,
                     storage_dir: 2,
                     filename: 2,
                     validate: 1
    end
  end
end
"#;
        let analyzer = analyzer_with_dep_source(dep_src);
        assert!(
            analyzer
                .dep_callbacks
                .contains_key("Waffle.Definition.Storage"),
            "expected Waffle.Definition.Storage in dep_callbacks, got: {:?}",
            analyzer.dep_callbacks.keys().collect::<Vec<_>>()
        );
        let cbs = &analyzer.dep_callbacks["Waffle.Definition.Storage"];
        assert!(cbs.contains(&("storage_dir_prefix".to_string(), 0)));
        assert!(cbs.contains(&("storage_dir".to_string(), 2)));
        assert!(cbs.contains(&("filename".to_string(), 2)));
        assert!(cbs.contains(&("validate".to_string(), 1)));
    }

    #[test]
    fn dep_callbacks_synthesize_calls_for_overridden_functions() {
        let dep_src = r#"
defmodule MyLib do
  defmacro __using__(_opts) do
    quote do
      defoverridable process: 2, validate: 1
    end
  end
end
"#;
        let dir = tempfile::tempdir().unwrap();
        let lib_dir = dir.path().join("lib");
        std::fs::create_dir_all(&lib_dir).unwrap();
        std::fs::write(lib_dir.join("my_lib.ex"), dep_src).unwrap();
        let analyzer = ElixirAnalyzer::new().with_deps(dir.path());

        let user_src = r#"
defmodule MyApp.Worker do
  use MyLib

  def process(item, opts) do
    {item, opts}
  end

  def validate(item), do: {:ok, item}
end
"#;
        let f = tempfile::NamedTempFile::new().unwrap();
        let path = f.path().with_extension("ex");
        std::fs::write(&path, user_src).unwrap();
        let analysis = analyzer.analyze_file(&path).unwrap();

        assert!(
            has_call(&analysis, "process", 2),
            "process/2 should be marked used via dep callbacks"
        );
        assert!(
            has_call(&analysis, "validate", 1),
            "validate/1 should be marked used via dep callbacks"
        );
        drop(dir);
    }

    #[test]
    fn dep_callbacks_not_emitted_when_function_not_defined() {
        // If the user doesn't define the overridable, no synthetic call is emitted.
        let dep_src = r#"
defmodule MyLib do
  defmacro __using__(_opts) do
    quote do
      defoverridable process: 2
    end
  end
end
"#;
        let dir = tempfile::tempdir().unwrap();
        let lib_dir = dir.path().join("lib");
        std::fs::create_dir_all(&lib_dir).unwrap();
        std::fs::write(lib_dir.join("my_lib.ex"), dep_src).unwrap();
        let analyzer = ElixirAnalyzer::new().with_deps(dir.path());

        let user_src = r#"
defmodule MyApp.Worker do
  use MyLib
  # process/2 not defined here — using the library default
end
"#;
        let f = tempfile::NamedTempFile::new().unwrap();
        let path = f.path().with_extension("ex");
        std::fs::write(&path, user_src).unwrap();
        let analysis = analyzer.analyze_file(&path).unwrap();
        assert!(!has_call(&analysis, "process", 2));
        drop(dir);
    }

    #[test]
    fn dep_scanning_follows_transitive_use_chain() {
        // Mirrors Waffle's actual structure exactly:
        //   Waffle.Definition.__using__ → `use Waffle.Definition.Storage`
        //   Waffle.Definition.Storage.__using__ → defoverridable + @before_compile
        //   Waffle.Definition.Storage.__before_compile__ → injects def s3_object_headers/2
        //     (no defoverridable on s3_object_headers — the injected def IS the contract)
        let definition_src = r#"
defmodule Waffle.Definition do
  defmacro __using__(_opts) do
    quote do
      use Waffle.Definition.Storage
    end
  end
end
"#;
        let storage_src = r#"
defmodule Waffle.Definition.Storage do
  defmacro __using__(_) do
    quote do
      @acl :private
      @async true

      def bucket, do: Application.fetch_env!(:waffle, :bucket)
      def bucket({_file, _scope}), do: bucket()
      def asset_host, do: Application.get_env(:waffle, :asset_host)
      def filename(_, {file, _}), do: Path.basename(file.file_name, Path.extname(file.file_name))
      def storage_dir_prefix, do: Application.get_env(:waffle, :storage_dir_prefix, "")
      def storage_dir(_, _), do: Application.get_env(:waffle, :storage_dir, "uploads")
      def validate(_), do: true
      def default_url(version, _), do: default_url(version)
      def default_url(_), do: nil
      def __storage, do: Application.get_env(:waffle, :storage, Waffle.Storage.S3)

      defoverridable storage_dir_prefix: 0,
                     storage_dir: 2,
                     filename: 2,
                     validate: 1,
                     default_url: 1,
                     default_url: 2,
                     __storage: 0,
                     bucket: 0,
                     bucket: 1,
                     asset_host: 0

      @before_compile Waffle.Definition.Storage
    end
  end

  defmacro __before_compile__(_env) do
    quote do
      def acl(_, _), do: @acl
      def s3_object_headers(_, _), do: []
      def async, do: @async
      def remote_file_headers(_), do: []
    end
  end
end
"#;
        let dir = tempfile::tempdir().unwrap();
        let waffle_dir = dir.path().join("lib").join("waffle");
        let definition_dir = waffle_dir.join("definition");
        std::fs::create_dir_all(&waffle_dir).unwrap();
        std::fs::create_dir_all(&definition_dir).unwrap();
        std::fs::write(waffle_dir.join("definition.ex"), definition_src).unwrap();
        std::fs::write(definition_dir.join("storage.ex"), storage_src).unwrap();
        let analyzer = ElixirAnalyzer::new().with_deps(dir.path());

        let cbs = analyzer
            .dep_callbacks
            .get("Waffle.Definition")
            .expect("Waffle.Definition must be in dep_callbacks");
        assert!(
            cbs.contains(&("storage_dir".to_string(), 2)),
            "storage_dir/2 must propagate via defoverridable"
        );
        assert!(
            cbs.contains(&("validate".to_string(), 1)),
            "validate/1 must propagate via defoverridable"
        );
        assert!(
            cbs.contains(&("s3_object_headers".to_string(), 2)),
            "s3_object_headers/2 must propagate via __before_compile__ injected def"
        );

        let user_src = r#"
defmodule Image do
  use Waffle.Definition

  def s3_object_headers(_version, {file, _scope}), do: s3_object_headers(file)
  def storage_dir(version, {_file, scope}), do: "uploads/#{version}/#{scope.id}"
  def validate({file, _}), do: validate(file)
end
"#;
        let f = tempfile::NamedTempFile::new().unwrap();
        let path = f.path().with_extension("ex");
        std::fs::write(&path, user_src).unwrap();
        let analysis = analyzer.analyze_file(&path).unwrap();
        assert!(
            has_call(&analysis, "s3_object_headers", 2),
            "s3_object_headers/2 must be marked used"
        );
        assert!(
            has_call(&analysis, "storage_dir", 2),
            "storage_dir/2 must be marked used"
        );
        assert!(
            has_call(&analysis, "validate", 1),
            "validate/1 must be marked used"
        );
        drop(dir);
    }
}
