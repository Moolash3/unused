# Unused

A fast, language-aware CLI for detecting unused function definitions in your source code. Built in Rust.

```
▶ Elixir — 47 files scanned, 312 definitions total
  ✗ 3 unused functions found:

  lib/my_app/workers/email.ex
    line   42  send_welcome/1  (public)
    line   87  retry_failed/2  (public)

  lib/my_app/auth/token.ex
    line   15  decode_legacy/1  (public)

──────────────────────────────────────────────────
Summary: 47 files, 312 definitions, 3 unused
```

## Features

- **Elixir support** — understands multi-clause functions, default arguments, pipe operators, pattern matching, guards, and OTP behaviours
- **Macro-aware** — scans your `deps/` directory to detect `defoverridable` callbacks injected by libraries like Waffle, so overridden callbacks are never falsely flagged
- **Phoenix-aware** — recognises router action atoms, `as:` helper generation, scope prefixes, and `use MyAppWeb, :controller` patterns
- **Smart call detection** — handles `apply/3`, `Kernel.apply/3`, function captures (`&foo/1`), pipe calls with and without parentheses, and remote calls
- **Refactor hints** — when a function is unused, surfaces same-name calls at a different arity as a likely typo or refactor signal
- **Flexible exclusions** — exclude specific modules by name or entire directory trees from the report
- **Multiple output formats** — pretty-printed, JSON, or one-line summary

## Installation

### From source

```bash
git clone https://github.com/yourname/unused
cd unused
cargo build --release
# Binary at ./target/release/unused
```

## Options

```
USAGE:
    unused [OPTIONS] [PATH]

ARGS:
    [PATH]    Directory to scan (defaults to current directory)

OPTIONS:
    -l, --language <LANGUAGE>          Language to analyze [possible values: elixir]
    -f, --format <FORMAT>              Output format [default: pretty] [possible values: pretty, json, summary]
        --include-private              Include private functions in the report
    -q, --quiet                        Suppress all output except results
        --fail-on-unused               Exit with non-zero code if unused functions are found
        --deps <PATH>                  Path to the dependencies directory (e.g. deps/)
        --exclude <MODULE[,MODULE...]> Exclude modules from the report (repeatable)
        --exclude-dir <PATH[,PATH...]> Exclude directory paths from scanning (repeatable)
        --no-hints                     Suppress similar-call refactor hints
        --debug-deps                   Print the dep_callbacks table and exit (for debugging)
    -h, --help                         Print help
    -V, --version                      Print version
```

## Examples

```bash
# Exclude generated or factory modules
unused --exclude MyApp.Factory --exclude MyApp.DataCase

# Exclude multiple modules at once
unused --exclude MyApp.Factory,MyApp.DataCase

# Skip test support and migration directories
unused --exclude-dir test/support --exclude-dir priv/repo/migrations

# JSON output for use in CI or other tooling
unused --format json | jq '.[] | .unused_functions[] | .file'

# Fail the build if unused functions are found
unused --fail-on-unused

# Include private functions in the report
unused --include-private

# Explicit deps path (if not using the standard Mix layout)
unused --deps vendor/deps .
```

## How it works

unused performs static analysis without compiling your code:

1. **File discovery** — walks the source tree, skipping `.git`, `_build`, `deps`, and `node_modules` by default
2. **Parsing** — extracts function definitions and call sites from each file using language-specific regex patterns
3. **Dep scanning** — if a `deps/` directory is found, scans library source for `defoverridable` and `__before_compile__` declarations, following transitive `use` chains to build a complete table of macro-injected callbacks
4. **Cross-reference** — builds a global index of all call sites and checks each definition against it
5. **Reporting** — surfaces definitions with no matching call site, with optional refactor hints

### What it handles

| Pattern | Example | Notes |
|---|---|---|
| Direct calls | `foo(x)` | |
| Pipe with parens | `x \|> foo(y)` | arity = explicit args + 1 |
| Pipe without parens | `x \|> foo` | arity = 1 |
| Function captures | `&foo/1`, `&Mod.foo/2` | |
| Remote calls | `Mod.foo(x)` | |
| `apply/3` literal list | `apply(mod, :foo, [x])` | arity from list |
| `apply/3` variable | `apply(mod, :foo, args)` | arity unknown — matches any |
| Default arguments | `def foo(x, opts \\ [])` | all arities registered |
| Default header + body | `def foo(opts \\ [])\ndef foo(opts) do` | compiler delegation handled |
| OTP callbacks | `use GenServer`, `use Application` | |
| `__before_compile__` defs | Waffle, custom macros | via dep scan |
| Phoenix router dispatch | `get "/path", Controller, :action` | |
| Phoenix `use MyApp, :view` | Web module pattern | |
| Scoped route helpers | `scope "/api", as: :api` | prefixed helpers generated |

### Known limitations

- **Dynamic dispatch via variables** — `apply(mod, atom_var, args)` where the function name is a runtime variable cannot be resolved statically. cleancode records the call with unknown arity, which matches any definition of that name.
- **Metaprogramming** — functions generated entirely at compile time by macros (beyond the `defoverridable` patterns cleancode scans for) may appear unused. Use `--exclude` to suppress specific modules.
- **Cross-file dynamic dispatch** — patterns like `Permission.Create` mapping to `create/0` via `Macro.underscore` require application-specific knowledge. Use `--exclude` for modules that follow this pattern.

## CI integration

```yaml
# GitHub Actions
- name: Check for unused functions
  run: cleancode --fail-on-unused --exclude-dir test/support --format summary .
```

## Debugging dep scanning

If a library callback is still being flagged as unused, use `--debug-deps` to inspect what was extracted from deps:

```bash
cleancode --debug-deps .
```

This prints every module and callback pair found in deps — including the transitive `use` chain resolution — then exits without running the full analysis.

## Contributing

Contributions are welcome. Please open an issue before submitting a large PR so we can discuss the approach.

```bash
cargo test     # run the full test suite
cargo clippy   # lint
cargo fmt      # format
```

The language analyzers live in `src/languages/`. Each implements the `LanguageAnalyzer` trait — `analyze_file` returns a `FileAnalysis` containing `FunctionDef` and `FunctionCall` lists. The cross-reference logic and output formatting are shared across all languages, so adding a new language only requires the parsing layer.

## License

MIT
