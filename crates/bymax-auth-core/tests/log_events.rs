//! The log-event contract: every operational `tracing` call in the production sources names a
//! closed `RUST_AUTH_*` code, carries only closed or numeric fields, and the codes are the ones
//! the README's "Log events" table lists, with the same level, in both directions.
//!
//! The sources are read as text, so a call added without a code, with a field that could carry an
//! account, an address, a token or an error's text, or with a code the README does not list, fails
//! here instead of reaching a log pipeline.
//!
//! What a text scan can and cannot say: it sees the form of every argument (a `kind` is a
//! literal, a `cause` is bound from a closed classifier, a message capture is an allow-listed
//! name), but not the type behind a bare name such as `plane` or `%flow`. Those stay closed
//! because the functions that bind them take a `&'static str`, and a diff that loosens one is a
//! diff a reviewer reads. The scan also stops at the first inline `#[cfg(test)] mod name { }`
//! of a file, so a production call placed after it is not seen; the sources keep such a module
//! last.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// The argument forms, besides the `event` code and a `kind` literal, an event may carry. Each is
/// closed or numeric by what it names, not by its field name alone: a bare `cause` is bound from
/// a closed classification (see [`CLOSED_CAUSES`]), a plane or flow is a name the library fixes,
/// and a status or a count is a number. A new form has to be added here, which is the review.
const ALLOWED_ARGS: [&str; 8] = [
    "cause",
    "plane",
    "%flow",
    "context = ?ctx",
    "failed = count",
    "%method",
    "route = %pattern",
    "status = response.status",
];

/// The functions a `let cause = ...` may bind from: each returns a `&'static str` out of a
/// closed set and never formats the error it was given.
const CLOSED_CAUSES: [&str; 5] = [
    "crate::services::failure_cause(",
    "failure_cause(",
    "unmigrated_cause(",
    "unsent_cause(",
    "provider_cause(",
];

/// The inline captures a message may name. Each is a `&'static str` the library fixes (a logout
/// step, a cache outcome), so a message carries no account, address or error text. A capture in
/// any other name, or a positional `{}`, has to be added here, which is the review.
const ALLOWED_CAPTURES: [&str; 2] = ["step", "outcome"];

/// The crates of the `tracing` family production code does not name: a call is `tracing::<level>!`.
const TRACING_CRATES: [&str; 5] = [
    "tracing_core",
    "tracing_log",
    "tracing_subscriber",
    "tracing_appender",
    "tracing_attributes",
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
    let Ok(entries) = fs::read_dir(dir) else { unreachable!() };
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
        let Ok(members) = fs::read_dir(root.join(group)) else { unreachable!() };
        for member in members.flatten() {
            rust_files(&member.path().join("src"), &mut files);
        }
    }
    files.retain(|path| {
        let name = path.to_string_lossy();
        !name.ends_with("_tests.rs")
            && !name.ends_with("/tests.rs")
            && !name.ends_with("log_capture.rs")
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
        let Ok(source) = fs::read_to_string(&path) else { unreachable!() };
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

/// Whether `arg`, with its whitespace collapsed, is a form an event may carry.
fn is_allowed_arg(arg: &str) -> bool {
    let arg = arg.split_whitespace().collect::<Vec<_>>().join(" ");
    let literal = |name: &str| {
        arg.strip_prefix(name)
            .and_then(|rest| rest.strip_prefix(" = \""))
            .is_some_and(|rest| rest.ends_with('"') && !rest[..rest.len() - 1].contains('"'))
    };
    ALLOWED_ARGS.contains(&arg.as_str()) || literal("kind") || arg == "kind = event"
}

#[test]
fn every_field_is_closed_or_numeric() {
    let mut offenders = Vec::new();
    for call in all_calls() {
        for arg in &call.args {
            let is_code = field_name(arg).as_deref() == Some("event");
            if field_name(arg).is_none() || is_code || is_allowed_arg(arg) {
                continue;
            }
            offenders.push(format!("{}:{} field `{arg}`", call.file, call.line));
        }
    }
    assert!(
        offenders.is_empty(),
        "fields that could carry an account or error text: {offenders:?}"
    );
}

#[test]
fn a_field_form_is_rejected_when_its_value_is_not_closed() {
    for allowed in [
        "cause",
        "kind = \"mfa_enabled\"",
        "kind = event",
        "%flow",
        "status = response.status",
    ] {
        assert!(is_allowed_arg(allowed), "{allowed}");
    }
    for refused in [
        "kind = _email",
        "cause = %error",
        "%cause",
        "kind = \"a\" + email",
        "email = %masked",
        "plane = tenant_id",
        "?cause",
    ] {
        assert!(!is_allowed_arg(refused), "{refused}");
    }
}

#[test]
fn a_cause_is_bound_from_a_closed_classification() {
    let root = workspace_root();
    let mut unbound = Vec::new();
    for path in production_sources() {
        let Ok(source) = fs::read_to_string(&path) else { unreachable!() };
        let text = production_part(&source);
        for (at, _) in text.match_indices("let cause = ") {
            let rhs = text[at + "let cause = ".len()..]
                .split(';')
                .next()
                .unwrap_or_default();
            if !CLOSED_CAUSES
                .iter()
                .any(|closed| rhs.trim_start().starts_with(closed))
            {
                let name = path
                    .strip_prefix(&root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned();
                unbound.push(format!("{name}: let cause = {}", rhs.trim()));
            }
        }
    }
    assert!(
        unbound.is_empty(),
        "a cause bound from something other than a closed classification: {unbound:?}"
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

/// The inline captures of a format string literal, `{name}` and `{name:spec}`, with `{{` and
/// `}}` escapes skipped; a positional `{}` is the empty name.
fn captures_of(literal: &str) -> Vec<String> {
    let inner = literal.trim_matches('"');
    let (mut names, mut chars) = (Vec::new(), inner.chars().peekable());
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
            }
            '{' => {
                let body: String = chars.by_ref().take_while(|c| *c != '}').collect();
                names.push(body.split(':').next().unwrap_or_default().to_owned());
            }
            _ => {}
        }
    }
    names
}

/// The message argument of a call: the one that is a string literal.
fn message_of(call: &Call) -> Option<&String> {
    call.args.iter().find(|arg| arg.starts_with('"'))
}

#[test]
fn every_message_names_only_closed_captures() {
    let mut offenders = Vec::new();
    for call in all_calls() {
        let Some(message) = message_of(&call) else { continue };
        for name in captures_of(message) {
            if !ALLOWED_CAPTURES.contains(&name.as_str()) {
                offenders.push(format!(
                    "{}:{} message capture `{{{name}}}`",
                    call.file, call.line
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a message may interpolate only a closed capture: {offenders:?}"
    );
}

#[test]
fn a_capture_is_read_out_of_a_message_literal() {
    assert_eq!(captures_of("\"{step}\""), ["step"]);
    assert_eq!(
        captures_of("\"a {outcome}; b {x:?} {}\""),
        ["outcome", "x", ""]
    );
    assert!(captures_of("\"a {{braced}} message\"").is_empty());
}

/// `text` with every comment and the inside of every string, raw string and char literal blanked
/// to spaces, so what is left is code: an identifier in a doc line or in a message is not a use
/// of it. The flag is `false` when the text ends inside a string or a block comment, which means
/// the lexer lost its place and what it blanked cannot be trusted.
fn lex_code(text: &str) -> (String, bool) {
    let chars: Vec<char> = text.chars().collect();
    let blank = |c: char| if c == '\n' { '\n' } else { ' ' };
    let (mut out, mut at) = (String::with_capacity(text.len()), 0_usize);
    let mut block_depth = 0_usize;
    while at < chars.len() {
        let (c, next) = (chars[at], chars.get(at + 1).copied());
        if block_depth > 0 {
            let (open, close) = (c == '/' && next == Some('*'), c == '*' && next == Some('/'));
            block_depth = block_depth + usize::from(open) - usize::from(close);
            let width = if open || close { 2 } else { 1 };
            out.extend(chars[at..at + width].iter().map(|c| blank(*c)));
            at += width;
        } else if c == '/' && next == Some('/') {
            while at < chars.len() && chars[at] != '\n' {
                out.push(' ');
                at += 1;
            }
        } else if c == '/' && next == Some('*') {
            block_depth = 1;
            out.push_str("  ");
            at += 2;
        } else if let Some(width) = literal_width(&chars, at) {
            out.push(chars[at]);
            out.extend(chars[at + 1..at + width - 1].iter().map(|c| blank(*c)));
            out.push(chars[at + width - 1]);
            at += width;
        } else if c == '"' {
            // An opening quote with no closing one: the lexer lost its place.
            return (out, false);
        } else {
            out.push(c);
            at += 1;
        }
    }
    (out, block_depth == 0)
}

/// Whether the `r` at `chars[at]` opens a raw string: it follows no identifier character, or only
/// a `b` or `c` that itself follows none (`r"..."`, `br#"..."#`, `cr"..."`), unlike the `r` that
/// ends an identifier.
fn raw_string_starts_here(chars: &[char], at: usize) -> bool {
    let ident = |i: usize| chars[i].is_alphanumeric() || chars[i] == '_';
    match at {
        0 => true,
        1 => !ident(0) || matches!(chars[0], 'b' | 'c'),
        _ => !ident(at - 1) || (matches!(chars[at - 1], 'b' | 'c') && !ident(at - 2)),
    }
}

/// The width of the string, raw string or char literal that starts at `chars[at]`, or `None` when
/// none does there (a lifetime such as `'a` is not a literal).
fn literal_width(chars: &[char], at: usize) -> Option<usize> {
    let find_close = |from: usize, close: &dyn Fn(usize) -> bool| {
        (from..chars.len()).find(|i| close(*i)).map(|i| i + 1 - at)
    };
    match chars[at] {
        '"' => {
            let mut i = at + 1;
            while i < chars.len() {
                match chars[i] {
                    '\\' => i += 1,
                    '"' => return Some(i + 1 - at),
                    _ => {}
                }
                i += 1;
            }
            None
        }
        'r' if raw_string_starts_here(chars, at) => {
            let hashes = chars[at + 1..].iter().take_while(|c| **c == '#').count();
            (chars.get(at + 1 + hashes) == Some(&'"')).then_some(())?;
            find_close(at + 2 + hashes, &|i| {
                chars[i] == '"' && (1..=hashes).all(|k| chars.get(i + k) == Some(&'#'))
            })
            .map(|width| width + hashes)
        }
        '\'' => match (chars.get(at + 1), chars.get(at + 2), chars.get(at + 3)) {
            (Some('\\'), _, _) => find_close(at + 3, &|i| chars[i] == '\''),
            (Some(c), Some('\''), _) if *c != '\'' => Some(3),
            _ => None,
        },
        _ => None,
    }
}

/// `text` with comments and literals blanked; see [`lex_code`].
fn code_only(text: &str) -> String {
    lex_code(text).0
}

/// Where `text`, read as code, names `tracing` in any way but the one spelling the scan reads,
/// `tracing::<level>!(`, and every other `tracing` macro form. Production code names a call that
/// one way so the scan sees all of them: an import (`use tracing::warn as log_warn;`, a glob, an
/// `extern crate`), `tracing::event!`, `tracing::span!`, `#[tracing::instrument]`, a `tracing_*`
/// crate, whitespace inside the path, or a bare level macro whose import the scan cannot see.
fn unscanned_forms(text: &str) -> Vec<String> {
    let code = code_only(text);
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut found = Vec::new();
    for (at, _) in code.match_indices("tracing") {
        let word_end = code[at..]
            .find(|c: char| !is_ident(c))
            .map_or(code.len(), |n| at + n);
        let word = &code[at..word_end];
        let names_the_crate = word == "tracing" || TRACING_CRATES.contains(&word);
        if code[..at].chars().next_back().is_some_and(is_ident) || !names_the_crate {
            continue;
        }
        let read = LEVELS.iter().any(|level| {
            code[at..]
                .strip_prefix("tracing::")
                .and_then(|rest| rest.strip_prefix(level))
                .is_some_and(|rest| rest.starts_with("!("))
        });
        if !read {
            let end = code[at..].find('\n').map_or(code.len(), |n| at + n);
            found.push(code[at..end].trim().to_owned());
        }
    }
    for (at, _) in code.match_indices('!') {
        let before = &code[..at];
        let name = &before[before.rfind(|c: char| !is_ident(c)).map_or(0, |i| i + 1)..];
        if LEVELS.contains(&name) && !before.trim_end_matches(is_ident).ends_with("tracing::") {
            found.push(format!("{name}!"));
        }
    }
    found
}

#[test]
fn the_scan_sees_every_form_a_tracing_call_can_take() {
    let offenders: Vec<String> = production_sources()
        .iter()
        .filter_map(|path| {
            let source = fs::read_to_string(path).ok()?;
            let part = production_part(&source);
            if !lex_code(part).1 {
                return Some(format!("{}: the lexer lost its place", path.display()));
            }
            let forms = unscanned_forms(part);
            (!forms.is_empty()).then(|| format!("{}: {forms:?}", path.display()))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "a tracing form the scan does not read: {offenders:?}"
    );
}

#[test]
fn the_unscanned_forms_are_recognised() {
    for bypass in [
        "use tracing::warn;\nwarn!(event = \"RUST_AUTH_X\");",
        "use tracing::warn as log_warn;\nlog_warn!(\"x {email}\", email = email);",
        "use tracing::*;",
        "pub use ::tracing::{warn, info};",
        "extern crate tracing as t;\nt::warn!(x);",
        "use tracing as t;",
        "tracing::event!(Level::WARN, \"x\");",
        "tracing::span!(Level::INFO, \"x\");",
        "#[tracing::instrument]\nfn f() {}",
        "tracing :: warn!(x);",
        "tracing::warn !(x);",
        "tracing::warn! (x);",
        "tracing_core::Event::dispatch(x);",
        "info!(x);",
        "let q = '\"'; use tracing::warn as w; w!(x); let s = \"a\";",
        "let q = '\\''; let s = r#\"say \"hi\"#; use tracing::warn as w;",
        "let s = r##\"a \"# b\"##; use tracing::warn as w;",
        "let s = br#\"unused \"#; use tracing::warn as w; w!(x); let tail = \"x\";",
        "let s = cr#\"say \" hi\"#; use tracing::warn as w;",
    ] {
        assert!(!unscanned_forms(bypass).is_empty(), "{bypass}");
    }
    for read in [
        "tracing::warn!(event = \"RUST_AUTH_X\");",
        "::tracing::error!(event = \"RUST_AUTH_X\");",
        "debug_assert!(x);",
        "assert!(x); format!(\"{x}\");",
        "// uses tracing::event! and `use tracing::warn;` in a note\nlet x = 1;",
        "/// the `tracing` crate\n/* use tracing::warn; */ let x = \"a tracing b\";",
        "let tracing_enabled = true;",
        "let q = '\"'; let s = \"tracing::event!\"; let l: &'a str = r#\"use tracing::warn;\"#;",
        "let r#type = 1; let q = 'x';",
    ] {
        assert!(
            unscanned_forms(read).is_empty(),
            "{read}: {:?}",
            unscanned_forms(read)
        );
    }
}

#[test]
fn a_lexer_that_loses_its_place_is_reported() {
    assert!(lex_code("let s = \"closed\"; // done").1);
    assert!(lex_code("let q = '\"'; let s = r#\"a \" b\"#;").1);
    assert!(lex_code("let s = br#\"say \" hi\"#; let t = cr\"x\";").1);
    assert!(lex_code("let bar = 1; let s = \"x\";").1);
    assert!(!lex_code("let s = \"never closed;").1);
    assert!(!lex_code("/* never closed").1);
}
