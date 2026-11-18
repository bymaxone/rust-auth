//! The log-event contract: every operational `tracing` call in the production sources names a
//! closed `RUST_AUTH_*` code, carries only closed or numeric fields, and the codes are the ones
//! the README's "Log events" table lists, with the same level, in both directions.
//!
//! The sources are read as text, so a call added without a code, with a field that could carry an
//! account, an address, a token or an error's text, or with a code the README does not list, fails
//! here instead of reaching a log pipeline.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// The only field names an event may carry: the code, a closed `cause` written bare (a
/// `&'static str`, never `%cause` or `?cause`, which would format an error), a plane, a flow, a
/// status, a number, or a name the code itself fixes.
const ALLOWED_FIELDS: [&str; 12] = [
    "event", "cause", "plane", "flow", "status", "failed", "count", "context", "method", "route",
    "step", "kind",
];

/// The levels a `tracing` macro names.
const LEVELS: [&str; 5] = ["error", "warn", "info", "debug", "trace"];

/// One `tracing` call found in a production source.
struct Call {
    file: String,
    line: usize,
    level: String,
    args: Vec<String>,
}

/// The workspace root, two levels above this crate.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .unwrap_or_default()
}

/// Every `.rs` file below `dir`, recursively.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The production sources: each crate's and binding's `src`, without test helpers or test files.
fn production_sources() -> Vec<PathBuf> {
    let root = workspace_root();
    let mut files = Vec::new();
    for group in ["crates", "bindings"] {
        let Ok(members) = fs::read_dir(root.join(group)) else { continue };
        for member in members.flatten() {
            rust_files(&member.path().join("src"), &mut files);
        }
    }
    files.retain(|path| {
        let name = path.to_string_lossy();
        !name.ends_with("_tests.rs") && !name.ends_with("log_capture.rs")
    });
    files.sort();
    files
}

/// The text of `source` before its inline `#[cfg(test)] mod ... { }` block, if it has one. A
/// `#[cfg(test)] mod name;` declaration only points at another file, so it ends nothing.
fn production_part(source: &str) -> &str {
    let mut from = 0;
    while let Some(at) = source[from..].find("#[cfg(test)]") {
        let start = from + at;
        let after = source[start + "#[cfg(test)]".len()..].trim_start();
        let after = after.strip_prefix("pub(crate) ").unwrap_or(after);
        let declaration = after
            .find([';', '{'])
            .map(|at| (after.starts_with("mod "), &after[at..]));
        if declaration.is_some_and(|(is_mod, rest)| is_mod && rest.starts_with('{')) {
            return &source[..start];
        }
        from = start + 1;
    }
    source
}

/// The index just past the `)` that closes the call whose arguments start at `start`.
fn close_of(text: &str, start: usize) -> usize {
    let bytes = text.as_bytes();
    let (mut depth, mut in_string, mut at) = (1_usize, false, start);
    while at < bytes.len() && depth > 0 {
        match bytes[at] {
            b'\\' if in_string => at += 1,
            b'"' => in_string = !in_string,
            b'(' if !in_string => depth += 1,
            b')' if !in_string => depth -= 1,
            _ => {}
        }
        at += 1;
    }
    at
}

/// The top-level comma-separated arguments of a call body.
fn split_args(body: &str) -> Vec<String> {
    let (mut args, mut current) = (Vec::new(), String::new());
    let (mut depth, mut in_string, mut chars) = (0_i32, false, body.chars());
    while let Some(c) = chars.next() {
        match c {
            '\\' if in_string => {
                current.push(c);
                current.extend(chars.next());
                continue;
            }
            '"' => in_string = !in_string,
            '(' | '[' | '{' if !in_string => depth += 1,
            ')' | ']' | '}' if !in_string => depth -= 1,
            ',' if !in_string && depth == 0 => {
                args.push(current.trim().to_owned());
                current.clear();
                continue;
            }
            _ => {}
        }
        current.push(c);
    }
    if !current.trim().is_empty() {
        args.push(current.trim().to_owned());
    }
    args
}

/// Every `tracing::<level>!(...)` call in one source's production part.
fn calls_in(file: &str, source: &str) -> Vec<Call> {
    let text = production_part(source);
    let mut calls = Vec::new();
    for level in LEVELS {
        let needle = format!("tracing::{level}!(");
        for (at, _) in text.match_indices(&needle) {
            let start = at + needle.len();
            let end = close_of(text, start);
            calls.push(Call {
                file: file.to_owned(),
                line: text[..at].matches('\n').count() + 1,
                level: level.to_owned(),
                args: split_args(&text[start..end - 1]),
            });
        }
    }
    calls
}

/// Every production call in the workspace.
fn all_calls() -> Vec<Call> {
    let root = workspace_root();
    let mut calls = Vec::new();
    for path in production_sources() {
        let Ok(source) = fs::read_to_string(&path) else { continue };
        let name = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        calls.extend(calls_in(&name, &source));
    }
    calls
}

/// The field name of one argument, or `None` for the `target:` argument and the message.
fn field_name(arg: &str) -> Option<String> {
    if arg.starts_with("target:") || arg.starts_with('"') {
        return None;
    }
    let bare = arg.trim_start_matches(['%', '?']);
    let end = bare
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(bare.len());
    Some(bare[..end].to_owned())
}

/// The code named by a call's `event = "RUST_AUTH_..."` argument.
fn code_of(call: &Call) -> Option<String> {
    call.args.iter().find_map(|arg| {
        let value = arg
            .strip_prefix("event")?
            .trim_start()
            .strip_prefix('=')?
            .trim();
        let code = value.strip_prefix('"')?.strip_suffix('"')?;
        code.starts_with("RUST_AUTH_").then(|| code.to_owned())
    })
}

/// The `(code -> level)` rows of the README's "Log events" table.
fn readme_events() -> BTreeMap<String, String> {
    let readme = fs::read_to_string(workspace_root().join("README.md")).unwrap_or_default();
    let section = readme.split("### Log events").nth(1).unwrap_or_default();
    let section = section.split("\n---").next().unwrap_or_default();
    section
        .lines()
        .filter_map(|line| {
            let mut cells = line.split('|').map(str::trim).skip(1);
            let code = cells.next()?.trim_matches('`');
            let level = cells.next()?;
            code.starts_with("RUST_AUTH_")
                .then(|| (code.to_owned(), level.to_owned()))
        })
        .collect()
}

#[test]
fn the_scan_finds_the_calls_it_is_meant_to_check() {
    let calls = all_calls();
    assert!(
        calls.len() > 100,
        "the scan read {} calls; the sources moved or the scan broke",
        calls.len()
    );
    assert!(
        calls
            .iter()
            .any(|call| call.file.ends_with("services/auth/login.rs"))
    );
    assert!(
        calls
            .iter()
            .any(|call| call.file.ends_with("bymax-auth-axum/src/response.rs"))
    );
}

#[test]
fn every_production_call_names_a_closed_code() {
    let missing: Vec<String> = all_calls()
        .iter()
        .filter(|call| code_of(call).is_none())
        .map(|call| format!("{}:{}", call.file, call.line))
        .collect();
    assert!(
        missing.is_empty(),
        "calls without `event = \"RUST_AUTH_...\"`: {missing:?}"
    );
}

#[test]
fn every_field_is_closed_or_numeric() {
    let mut offenders = Vec::new();
    for call in all_calls() {
        for arg in &call.args {
            let Some(name) = field_name(arg) else { continue };
            let is_bare = arg == &name;
            let closed_cause = name != "cause" || is_bare;
            if !ALLOWED_FIELDS.contains(&name.as_str()) || !closed_cause {
                offenders.push(format!("{}:{} field `{arg}`", call.file, call.line));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "fields that could carry an account or error text: {offenders:?}"
    );
}

#[test]
fn the_codes_in_the_sources_are_the_readme_table_with_the_same_levels() {
    let mut in_source: BTreeMap<String, String> = BTreeMap::new();
    let mut disagreeing = Vec::new();
    for call in all_calls() {
        let Some(code) = code_of(&call) else { continue };
        let level = in_source
            .entry(code.clone())
            .or_insert_with(|| call.level.clone());
        if *level != call.level {
            disagreeing.push(format!("{code} is {level} and {}", call.level));
        }
    }
    assert!(
        disagreeing.is_empty(),
        "one code at two levels: {disagreeing:?}"
    );
    let in_readme = readme_events();
    assert!(
        !in_readme.is_empty(),
        "the README has no `### Log events` table"
    );
    let undocumented: Vec<_> = in_source
        .keys()
        .filter(|c| !in_readme.contains_key(*c))
        .collect();
    let unemitted: Vec<_> = in_readme
        .keys()
        .filter(|c| !in_source.contains_key(*c))
        .collect();
    assert!(
        undocumented.is_empty() && unemitted.is_empty(),
        "in the sources but not the README: {undocumented:?}; in the README but not the sources: {unemitted:?}"
    );
    let wrong_level: Vec<_> = in_source
        .iter()
        .filter(|(code, level)| in_readme.get(*code).is_some_and(|row| row != *level))
        .map(|(code, level)| format!("{code}: source {level}, README {}", in_readme[code]))
        .collect();
    assert!(
        wrong_level.is_empty(),
        "levels that differ: {wrong_level:?}"
    );
}
