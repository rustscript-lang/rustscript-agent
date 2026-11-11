//! Telegram MarkdownV2 conversion and approval-card text.
//! Streaming previews stay plain. Only a finished body or an approval card
//! uses this module, and the card is emitted as MarkdownV2 directly.
use serde_json::Value;

const MAX_UTF16: usize = 4096;

pub(crate) fn utf16_units(text: &str) -> usize {
    text.chars().map(char::len_utf16).sum()
}

fn is_special(ch: char) -> bool {
    matches!(
        ch,
        '_' | '*'
            | '['
            | ']'
            | '('
            | ')'
            | '~'
            | '`'
            | '>'
            | '#'
            | '+'
            | '-'
            | '='
            | '|'
            | '{'
            | '}'
            | '.'
            | '!'
            | '\\'
    )
}

pub(crate) fn escape_markdown_v2(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        if is_special(ch) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

fn escape_code(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        if ch == '\\' || ch == '`' {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

pub(crate) fn format_markdown_v2(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '\r' && chars.get(index + 1) == Some(&'\n') {
            index += 1;
            continue;
        }
        if line_start(&chars, index) {
            if let Some(end) = fenced_block(&chars, index) {
                out.push_str(&render_fence(&chars[index..end]));
                index = end;
                continue;
            }
            if let Some(end) = heading_line(&chars, index) {
                let title = chars[skip_heading_marks(&chars, index)..end]
                    .iter()
                    .collect::<String>();
                out.push('*');
                out.push_str(&escape_markdown_v2(title.trim()));
                out.push('*');
                index = end;
                continue;
            }
            if chars[index] == '>' {
                out.push('>');
                index += 1;
                continue;
            }
            if is_list_marker(&chars, index) {
                out.push('\\');
                out.push(chars[index]);
                index += 1;
                continue;
            }
        }
        if chars[index] == '`'
            && let Some(end) = inline_code(&chars, index)
        {
            let body: String = chars[index + 1..end - 1].iter().collect();
            out.push('`');
            out.push_str(&escape_code(&body));
            out.push('`');
            index = end;
            continue;
        }
        if let Some(end) = paired_marker(&chars, index, &['*', '*']) {
            let inner: String = chars[index + 2..end - 2].iter().collect();
            out.push('*');
            out.push_str(&escape_markdown_v2(&inner));
            out.push('*');
            index = end;
            continue;
        }
        if let Some(end) = paired_marker(&chars, index, &['~', '~']) {
            let inner: String = chars[index + 2..end - 2].iter().collect();
            out.push('~');
            out.push_str(&escape_markdown_v2(&inner));
            out.push('~');
            index = end;
            continue;
        }
        if chars[index] == '*'
            && let Some(end) = single_span(&chars, index, '*')
        {
            let inner: String = chars[index + 1..end - 1].iter().collect();
            out.push('_');
            out.push_str(&escape_markdown_v2(&inner));
            out.push('_');
            index = end;
            continue;
        }
        if chars[index] == '['
            && let Some((text_end, url_end)) = link_span(&chars, index)
        {
            let label: String = chars[index + 1..text_end].iter().collect();
            let url: String = chars[text_end + 2..url_end].iter().collect();
            out.push('[');
            out.push_str(&escape_markdown_v2(&label));
            out.push(']');
            out.push('(');
            out.push_str(&escape_markdown_v2(&url));
            out.push(')');
            index = url_end + 1;
            continue;
        }
        if is_special(chars[index]) {
            out.push('\\');
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}

fn line_start(chars: &[char], index: usize) -> bool {
    index == 0 || chars[index - 1] == '\n'
}

fn heading_line(chars: &[char], index: usize) -> Option<usize> {
    let mut marks = 0;
    while index + marks < chars.len() && chars[index + marks] == '#' && marks < 6 {
        marks += 1;
    }
    if marks == 0 || chars.get(index + marks) != Some(&' ') {
        return None;
    }
    Some(line_end(chars, index))
}

fn skip_heading_marks(chars: &[char], index: usize) -> usize {
    let mut cursor = index;
    while cursor < chars.len() && chars[cursor] == '#' {
        cursor += 1;
    }
    if chars.get(cursor) == Some(&' ') {
        cursor + 1
    } else {
        index
    }
}

fn is_list_marker(chars: &[char], index: usize) -> bool {
    matches!(chars.get(index), Some('-' | '*' | '+')) && chars.get(index + 1) == Some(&' ')
}

fn line_end(chars: &[char], index: usize) -> usize {
    chars[index..]
        .iter()
        .position(|ch| *ch == '\n')
        .map(|offset| index + offset)
        .unwrap_or(chars.len())
}

fn fenced_block(chars: &[char], index: usize) -> Option<usize> {
    let open = fence_marker(chars, index)?;
    let mut cursor = open;
    if cursor < chars.len() && chars[cursor] == '\n' {
        cursor += 1;
    } else {
        return None;
    }
    while cursor < chars.len() {
        if let Some(close) = pure_fence_close_end(chars, cursor) {
            let mut end = close;
            if end < chars.len() && chars[end] == '\n' {
                end += 1;
            }
            return Some(end);
        }
        cursor += 1;
    }
    None
}

fn fence_marker(chars: &[char], index: usize) -> Option<usize> {
    if !line_start(chars, index) || chars.get(index) != Some(&'`') {
        return None;
    }
    let mut cursor = index;
    while cursor < chars.len() && chars[cursor] == '`' {
        cursor += 1;
    }
    if cursor - index < 3 {
        return None;
    }
    let rest = line_end(chars, cursor);
    if chars[cursor..rest].contains(&'`') {
        return None;
    }
    Some(rest)
}

fn pure_fence_close_end(chars: &[char], index: usize) -> Option<usize> {
    let close = fence_marker(chars, index)?;
    if chars[index..close].iter().all(|ch| *ch == '`') {
        Some(close)
    } else {
        None
    }
}

fn render_fence(chars: &[char]) -> String {
    let open_end = fence_marker(chars, 0).unwrap_or(0);
    let language: String = chars[3..open_end].iter().collect();
    let language = language.trim();
    let safe_language = language
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '+');
    let body_start = open_end + 1;
    let mut close = chars.len();
    let mut cursor = body_start;
    while cursor < chars.len() {
        if pure_fence_close_end(chars, cursor).is_some() {
            close = cursor;
            break;
        }
        cursor += 1;
    }
    let body: String = chars[body_start..close].iter().collect();
    let body = body.trim_end_matches(['\n', '\r']);
    let mut out = String::from("```");
    if safe_language && !language.is_empty() {
        out.push_str(language);
    }
    out.push('\n');
    out.push_str(&escape_code(body));
    out.push_str("\n```");
    out
}

fn inline_code(chars: &[char], index: usize) -> Option<usize> {
    if chars.get(index) != Some(&'`') {
        return None;
    }
    let end = chars[index + 1..]
        .iter()
        .position(|ch| *ch == '`' || *ch == '\n')?;
    if chars[index + 1 + end] != '`' {
        return None;
    }
    Some(index + 2 + end)
}

fn paired_marker(chars: &[char], index: usize, marker: &[char]) -> Option<usize> {
    if chars.len() < index + marker.len() || &chars[index..index + marker.len()] != marker {
        return None;
    }
    let mut cursor = index + marker.len();
    while cursor + marker.len() <= chars.len() {
        if &chars[cursor..cursor + marker.len()] == marker {
            if cursor == index + marker.len() {
                return None;
            }
            return Some(cursor + marker.len());
        }
        if chars[cursor] == '\n' {
            return None;
        }
        cursor += 1;
    }
    None
}

fn single_span(chars: &[char], index: usize, marker: char) -> Option<usize> {
    if chars.get(index) != Some(&marker) || chars.get(index + 1) == Some(&marker) {
        return None;
    }
    let mut cursor = index + 1;
    while cursor < chars.len() && chars[cursor] != '\n' {
        if chars[cursor] == marker && chars.get(cursor + 1) != Some(&marker) {
            if cursor == index + 1 {
                return None;
            }
            return Some(cursor + 1);
        }
        cursor += 1;
    }
    None
}

fn link_span(chars: &[char], index: usize) -> Option<(usize, usize)> {
    let text_end = chars[index + 1..]
        .iter()
        .position(|ch| *ch == ']' || *ch == '\n' || *ch == '[')?;
    let text_end = index + 1 + text_end;
    if chars.get(text_end) != Some(&']') || chars.get(text_end + 1) != Some(&'(') {
        return None;
    }
    let url_end = chars[text_end + 2..]
        .iter()
        .position(|ch| *ch == ')' || *ch == '\n' || ch.is_whitespace())?;
    let url_end = text_end + 2 + url_end;
    if chars.get(url_end) != Some(&')') {
        return None;
    }
    Some((text_end, url_end))
}

/// Finished-body chunks. `plain` is the original source fragment for that
/// chunk, not the visible rendering and not the whole message. Concatenating
/// the plains restores `source` exactly once.
pub(crate) fn paired_markdown_chunks(source: &str) -> Vec<(String, String)> {
    if source.is_empty() {
        return Vec::new();
    }
    let formatted = format_markdown_v2(source);
    if utf16_units(&formatted) <= MAX_UTF16 {
        return vec![(formatted, source.to_string())];
    }
    let chars: Vec<char> = source.chars().collect();
    let mut pairs = Vec::new();
    let mut pending = String::new();
    let mut index = 0;
    while index < chars.len() {
        if line_start(&chars, index)
            && let Some(end) = fenced_block(&chars, index)
        {
            flush_pending(&mut pending, &mut pairs);
            pairs.extend(split_oversized_fence(&chars[index..end]));
            index = end;
            continue;
        }
        pending.push(chars[index]);
        index += 1;
    }
    flush_pending(&mut pending, &mut pairs);
    if pairs.is_empty() {
        pairs.push((formatted, source.to_string()));
    }
    pairs
}

fn flush_pending(pending: &mut String, pairs: &mut Vec<(String, String)>) {
    if pending.is_empty() {
        return;
    }
    let source = std::mem::take(pending);
    let formatted = format_markdown_v2(&source);
    if utf16_units(&formatted) <= MAX_UTF16 {
        pairs.push((formatted, source));
        return;
    }
    pairs.extend(split_region_keeping_entities(&source));
}

fn split_region_keeping_entities(source: &str) -> Vec<(String, String)> {
    pack_atoms(region_atoms(source))
}

fn region_atoms(source: &str) -> Vec<(String, String)> {
    let chars: Vec<char> = source.chars().collect();
    let mut atoms = Vec::new();
    let mut carry = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '\r' && chars.get(index + 1) == Some(&'\n') {
            carry.push('\r');
            index += 1;
            continue;
        }
        if line_start(&chars, index) {
            if let Some(end) = heading_line(&chars, index) {
                let title = chars[skip_heading_marks(&chars, index)..end]
                    .iter()
                    .collect::<String>();
                let mut formatted = String::from("*");
                formatted.push_str(&escape_markdown_v2(title.trim()));
                formatted.push('*');
                let raw: String = chars[index..end].iter().collect();
                emit_atom(&mut atoms, &mut carry, formatted, raw);
                index = end;
                continue;
            }
            if chars[index] == '>' {
                emit_atom(&mut atoms, &mut carry, ">".to_string(), ">".to_string());
                index += 1;
                continue;
            }
            if is_list_marker(&chars, index) {
                emit_atom(
                    &mut atoms,
                    &mut carry,
                    format!("\\{}", chars[index]),
                    chars[index].to_string(),
                );
                index += 1;
                continue;
            }
        }
        if chars[index] == '`'
            && let Some(end) = inline_code(&chars, index)
        {
            let body: String = chars[index + 1..end - 1].iter().collect();
            let mut formatted = String::from("`");
            formatted.push_str(&escape_code(&body));
            formatted.push('`');
            let raw: String = chars[index..end].iter().collect();
            emit_atom(&mut atoms, &mut carry, formatted, raw);
            index = end;
            continue;
        }
        if let Some(end) = paired_marker(&chars, index, &['*', '*']) {
            let inner: String = chars[index + 2..end - 2].iter().collect();
            let mut formatted = String::from("*");
            formatted.push_str(&escape_markdown_v2(&inner));
            formatted.push('*');
            let raw: String = chars[index..end].iter().collect();
            emit_atom(&mut atoms, &mut carry, formatted, raw);
            index = end;
            continue;
        }
        if let Some(end) = paired_marker(&chars, index, &['~', '~']) {
            let inner: String = chars[index + 2..end - 2].iter().collect();
            let mut formatted = String::from("~");
            formatted.push_str(&escape_markdown_v2(&inner));
            formatted.push('~');
            let raw: String = chars[index..end].iter().collect();
            emit_atom(&mut atoms, &mut carry, formatted, raw);
            index = end;
            continue;
        }
        if chars[index] == '*'
            && let Some(end) = single_span(&chars, index, '*')
        {
            let inner: String = chars[index + 1..end - 1].iter().collect();
            let mut formatted = String::from("_");
            formatted.push_str(&escape_markdown_v2(&inner));
            formatted.push('_');
            let raw: String = chars[index..end].iter().collect();
            emit_atom(&mut atoms, &mut carry, formatted, raw);
            index = end;
            continue;
        }
        if chars[index] == '['
            && let Some((text_end, url_end)) = link_span(&chars, index)
        {
            let label: String = chars[index + 1..text_end].iter().collect();
            let url: String = chars[text_end + 2..url_end].iter().collect();
            let mut formatted = String::from("[");
            formatted.push_str(&escape_markdown_v2(&label));
            formatted.push(']');
            formatted.push('(');
            formatted.push_str(&escape_markdown_v2(&url));
            formatted.push(')');
            let raw: String = chars[index..=url_end].iter().collect();
            emit_atom(&mut atoms, &mut carry, formatted, raw);
            index = url_end + 1;
            continue;
        }
        let ch = chars[index];
        let formatted = if is_special(ch) {
            format!("\\{ch}")
        } else {
            ch.to_string()
        };
        emit_atom(&mut atoms, &mut carry, formatted, ch.to_string());
        index += 1;
    }
    if !carry.is_empty() {
        atoms.extend(split_plain_bounded(&carry));
    }
    atoms
}

fn emit_atom(
    atoms: &mut Vec<(String, String)>,
    carry: &mut String,
    formatted: String,
    mut source: String,
) {
    if !carry.is_empty() {
        source.insert_str(0, carry);
        carry.clear();
    }
    if utf16_units(&formatted) <= MAX_UTF16 && utf16_units(&source) <= MAX_UTF16 {
        atoms.push((formatted, source));
        return;
    }
    atoms.extend(split_plain_bounded(&source));
}

fn pack_atoms(atoms: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut formatted = String::new();
    let mut plain = String::new();
    let mut used_fmt = 0usize;
    let mut used_src = 0usize;
    for (piece, source) in atoms {
        let need_fmt = utf16_units(&piece);
        let need_src = utf16_units(&source);
        let overflows =
            used_fmt > 0 && (used_fmt + need_fmt > MAX_UTF16 || used_src + need_src > MAX_UTF16);
        if overflows {
            pairs.push((std::mem::take(&mut formatted), std::mem::take(&mut plain)));
            used_fmt = 0;
            used_src = 0;
        }
        if need_fmt > MAX_UTF16 || need_src > MAX_UTF16 {
            pairs.extend(split_plain_bounded(&source));
            continue;
        }
        formatted.push_str(&piece);
        plain.push_str(&source);
        used_fmt += need_fmt;
        used_src += need_src;
    }
    if !plain.is_empty() || !formatted.is_empty() {
        pairs.push((formatted, plain));
    }
    pairs
}

fn split_oversized_fence(chars: &[char]) -> Vec<(String, String)> {
    let source: String = chars.iter().collect();
    let formatted = render_fence(chars);
    if utf16_units(&formatted) <= MAX_UTF16 {
        return vec![(formatted, source)];
    }
    let open_end = fence_marker(chars, 0).unwrap_or(0);
    let language: String = chars[3..open_end].iter().collect();
    let language = language.trim();
    let safe_language = language
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '+');
    let body_start = (open_end + 1).min(chars.len());
    let mut close = chars.len();
    let mut cursor = body_start;
    while cursor < chars.len() {
        if pure_fence_close_end(chars, cursor).is_some() {
            close = cursor;
            break;
        }
        cursor += 1;
    }
    let body: Vec<char> = chars[body_start..close].to_vec();
    let mut display_end = body.len();
    while display_end > 0 && matches!(body[display_end - 1], '\n' | '\r') {
        display_end -= 1;
    }
    let mut open_fmt = String::from("```");
    if safe_language && !language.is_empty() {
        open_fmt.push_str(language);
    }
    open_fmt.push('\n');
    let close_fmt = "\n```";
    let overhead = utf16_units(&open_fmt) + utf16_units(close_fmt);
    if overhead >= MAX_UTF16 {
        return split_plain_bounded(&source);
    }
    let budget = MAX_UTF16 - overhead;
    let open_src: String = chars[..body_start].iter().collect();
    let close_src: String = chars[close..].iter().collect();
    let trimmed_tail: String = body[display_end..].iter().collect();
    let frame = FenceFrame {
        open_fmt: &open_fmt,
        close_fmt,
        open_src: &open_src,
    };
    let mut pairs = Vec::new();
    let mut fmt_body = String::new();
    let mut src_body = String::new();
    let mut used = 0usize;
    let mut started = false;
    for ch in body[..display_end].iter().copied() {
        let escaped = escape_code(&ch.to_string());
        let need = utf16_units(&escaped).max(1);
        if used > 0 && used + need > budget {
            push_fence_piece(&mut pairs, &frame, &fmt_body, &src_body, "", started);
            started = true;
            fmt_body.clear();
            src_body.clear();
            used = 0;
        }
        fmt_body.push_str(&escaped);
        src_body.push(ch);
        used += need;
    }
    let tail = format!("{trimmed_tail}{close_src}");
    push_fence_piece(&mut pairs, &frame, &fmt_body, &src_body, &tail, started);
    if pairs.is_empty() {
        return split_plain_bounded(&source);
    }
    pairs
}

struct FenceFrame<'a> {
    open_fmt: &'a str,
    close_fmt: &'a str,
    open_src: &'a str,
}

fn push_fence_piece(
    pairs: &mut Vec<(String, String)>,
    frame: &FenceFrame<'_>,
    fmt_body: &str,
    src_body: &str,
    tail_src: &str,
    started: bool,
) {
    let mut formatted = String::from(frame.open_fmt);
    formatted.push_str(fmt_body);
    formatted.push_str(frame.close_fmt);
    let mut plain = String::new();
    if !started {
        plain.push_str(frame.open_src);
    }
    plain.push_str(src_body);
    plain.push_str(tail_src);
    if utf16_units(&formatted) > MAX_UTF16 || utf16_units(&plain) > MAX_UTF16 {
        pairs.extend(split_plain_bounded(&plain));
        return;
    }
    pairs.push((formatted, plain));
}

fn split_plain_bounded(source: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut formatted = String::new();
    let mut plain = String::new();
    let mut used = 0usize;
    for ch in source.chars() {
        let escaped = escape_markdown_v2(&ch.to_string());
        let need = utf16_units(&escaped).max(1);
        if used > 0 && used + need > MAX_UTF16 {
            pairs.push((std::mem::take(&mut formatted), std::mem::take(&mut plain)));
            used = 0;
        }
        formatted.push_str(&escaped);
        plain.push(ch);
        used += need;
    }
    if !plain.is_empty() {
        pairs.push((formatted, plain));
    }
    pairs
}

pub(crate) fn format_timeout_ms(timeout_ms: u64) -> String {
    if timeout_ms == 0 {
        return "未指定（工具默认）".to_string();
    }
    if timeout_ms.is_multiple_of(1000) {
        format!("{} 秒", timeout_ms / 1000)
    } else {
        format!("{timeout_ms} 毫秒")
    }
}

pub(crate) fn quote_display(argument: &str) -> String {
    format!("'{}'", argument.replace('\'', "'\\''"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApprovalCard {
    pub text: String,
    pub attach_keyboard: bool,
}

pub(crate) fn approval_card(shown: &str, allow_terminal_buttons: bool) -> ApprovalCard {
    if shown.trim().is_empty() || shown == "Action preview unavailable; do not approve this action."
    {
        return withheld();
    }
    let Some((kind, payload)) = shown.split_once(' ') else {
        return readable_unknown(shown);
    };
    let payload = payload.trim();
    if !payload.starts_with('{') {
        return readable_unknown(shown);
    }
    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        return withheld();
    };
    let card = match kind {
        "terminal" => terminal_card(&value, allow_terminal_buttons),
        "write_file" => file_card("写入文件", "替换文件", &value),
        "patch" => patch_card(&value),
        "process" => process_card(&value),
        _ => readable_unknown(shown),
    };
    fit_card(card)
}

fn withheld() -> ApprovalCard {
    ApprovalCard {
        text: "需要授权。完整预览不可用，不能在此确认。".to_string(),
        attach_keyboard: false,
    }
}

fn fit_card(card: ApprovalCard) -> ApprovalCard {
    if utf16_units(&card.text) <= MAX_UTF16 {
        return card;
    }
    withheld()
}

fn terminal_card(value: &Value, allow_terminal_buttons: bool) -> ApprovalCard {
    let program = value.get("program").and_then(Value::as_str).unwrap_or("");
    let argv = string_array(value.get("argv"));
    let cwd = value.get("cwd").and_then(Value::as_str);
    let timeout = value.get("timeout_ms").and_then(Value::as_u64);
    let background = value.get("background").and_then(Value::as_bool);
    let complete = !program.is_empty()
        && argv.as_ref().is_some_and(|args| !args.is_empty())
        && cwd.is_some()
        && timeout.is_some()
        && background.is_some();
    let display = display_argv(program, argv.as_deref().unwrap_or(&[]));
    let directory = match cwd {
        Some("") | None => "当前工作区".to_string(),
        Some(path) => escape_markdown_v2(path),
    };
    let mut text = String::from("*需要授权 · 执行命令*\n\n```\n");
    text.push_str(&escape_code(&display));
    text.push_str("\n```\n目录：");
    text.push_str(&directory);
    if let Some(timeout_ms) = timeout {
        text.push_str("\n工具超时：");
        text.push_str(&format_timeout_ms(timeout_ms));
    }
    if let Some(background) = background {
        text.push_str(if background {
            "\n方式：后台"
        } else {
            "\n方式：前台"
        });
    }
    ApprovalCard {
        text,
        attach_keyboard: complete && allow_terminal_buttons,
    }
}

fn display_argv(program: &str, argv: &[String]) -> String {
    let mut tokens = Vec::new();
    if !program.is_empty() && argv.first().map(String::as_str) != Some(program) {
        tokens.push(quote_display(program));
    }
    for argument in argv {
        tokens.push(quote_display(argument));
    }
    if tokens.is_empty() && !program.is_empty() {
        tokens.push(quote_display(program));
    }
    tokens.join(" ")
}

fn file_card(title: &str, operation: &str, value: &Value) -> ApprovalCard {
    let Some(path) = value.get("path").and_then(Value::as_str) else {
        return withheld();
    };
    if path.is_empty() {
        return withheld();
    }
    ApprovalCard {
        text: format!(
            "*需要授权 · {title}*\n\n路径：`{}`\n操作：{operation}",
            escape_code(path)
        ),
        attach_keyboard: true,
    }
}

fn patch_card(value: &Value) -> ApprovalCard {
    let Some(path) = value.get("path").and_then(Value::as_str) else {
        return withheld();
    };
    let scope = if value.get("replace_all").and_then(Value::as_bool) == Some(true) {
        "全部"
    } else {
        "单处"
    };
    ApprovalCard {
        text: format!(
            "*需要授权 · 修改文件*\n\n路径：`{}`\n操作：替换文本\n范围：{scope}",
            escape_code(path)
        ),
        attach_keyboard: !path.is_empty(),
    }
}

fn process_card(value: &Value) -> ApprovalCard {
    let operation = value.get("operation").and_then(Value::as_str).unwrap_or("");
    let process_id = value
        .get("process_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    if operation.is_empty() || process_id.is_empty() {
        return withheld();
    }
    let mut text = format!(
        "*需要授权 · 进程操作*\n\n操作：{}\n进程：`{}`",
        escape_markdown_v2(operation),
        escape_code(process_id)
    );
    if let Some(timeout_ms) = value.pointer("/options/timeout_ms").and_then(Value::as_u64) {
        text.push_str("\n工具超时：");
        text.push_str(&format_timeout_ms(timeout_ms));
    }
    ApprovalCard {
        text,
        attach_keyboard: true,
    }
}

fn readable_unknown(shown: &str) -> ApprovalCard {
    let text = format!("*需要授权*\n\n```\n{}\n```", escape_code(shown));
    ApprovalCard {
        text,
        attach_keyboard: utf16_units(shown) > 0,
    }
}

fn string_array(value: Option<&Value>) -> Option<Vec<String>> {
    let items = value?.as_array()?;
    items
        .iter()
        .map(|item| item.as_str().map(str::to_string))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn markdown_v2_converts_common_marks_and_escapes_the_rest() {
        assert_eq!(format_markdown_v2("**bold**"), "*bold*");
        assert_eq!(format_markdown_v2("# Title"), "*Title*");
        assert_eq!(format_markdown_v2("*em*"), "_em_");
        assert_eq!(format_markdown_v2("~~gone~~"), "~gone~");
        assert_eq!(
            format_markdown_v2("[a](https://example.com)"),
            "[a](https://example\\.com)"
        );
        assert_eq!(format_markdown_v2("`a_b`"), "`a_b`");
        assert_eq!(format_markdown_v2("a_b!"), "a\\_b\\!");
        assert_eq!(format_markdown_v2("- item!"), "\\- item\\!");
        let fenced = format_markdown_v2("```\r\nkeep`me\\r\r\n```");
        assert!(fenced.starts_with("```\n"));
        assert!(fenced.contains("keep\\`me\\\\r"));
        assert!(fenced.ends_with("\n```"));
    }

    #[test]
    fn chunks_keep_fences_closed_and_within_utf16() {
        let body = "x".repeat(5000);
        let text = format!("```\n{body}\n```");
        let pairs = paired_markdown_chunks(&text);
        assert!(pairs.len() > 1);
        assert!(pairs.iter().all(|(chunk, plain)| {
            utf16_units(chunk) <= MAX_UTF16 && utf16_units(plain) <= MAX_UTF16
        }));
        for (chunk, _) in &pairs {
            let markers = chunk.lines().filter(|line| line.starts_with("```")).count();
            assert_eq!(markers % 2, 0, "{chunk}");
        }
        let recovered: String = pairs
            .iter()
            .map(|(chunk, _)| {
                chunk
                    .lines()
                    .filter(|line| !line.starts_with("```"))
                    .collect::<Vec<_>>()
                    .join("")
            })
            .collect();
        assert_eq!(recovered, body);
        let plains: String = pairs.iter().map(|(_, plain)| plain.as_str()).collect();
        assert_eq!(plains, text);
    }

    /// A tick-word line inside a closed fence is code. Only a pure tick line
    /// closes it, so the later sentinel stays in the formatted body.
    #[test]
    fn fence_body_keeps_tick_word_line_until_pure_close() {
        let source = concat!(
            "```rust\n",
            "alpha\n",
            "```word\n",
            "SENTINEL_AFTER_FALSE_CLOSE\n",
            "keep\\slash\n",
            "```\n",
        );
        let expected = concat!(
            "```rust\n",
            "alpha\n",
            "\\`\\`\\`word\n",
            "SENTINEL_AFTER_FALSE_CLOSE\n",
            "keep\\\\slash\n",
            "```",
        );
        assert_eq!(format_markdown_v2(source), expected);
        let pairs = paired_markdown_chunks(source);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, expected);
        assert_eq!(pairs[0].1, source);
    }

    /// Same pure-close rule once a fence crosses the 4096 budget. Chunk code
    /// bodies restore the source code once, including the tick-word line.
    #[test]
    fn long_fence_keeps_tick_word_line_across_chunks() {
        fn unescape_fence_code(body: &str) -> String {
            let mut out = String::new();
            let mut chars = body.chars();
            while let Some(ch) = chars.next() {
                if ch == '\\' {
                    out.push(chars.next().expect("fence escape pair"));
                } else {
                    out.push(ch);
                }
            }
            out
        }

        let before = "a".repeat(3000);
        let after = "b".repeat(3000);
        let code = format!("{before}\n```word\nSENTINEL_AFTER_FALSE_CLOSE\nkeep\\slash\n{after}");
        let source = format!("```rust\n{code}\n```\n");
        let pairs = paired_markdown_chunks(&source);
        assert!(pairs.len() > 1, "fence must cross the 4096 budget");
        let mut recovered = String::new();
        let mut plains = String::new();
        for (chunk, plain) in &pairs {
            assert!(utf16_units(chunk) <= MAX_UTF16);
            assert!(utf16_units(plain) <= MAX_UTF16);
            let rest = chunk
                .strip_prefix("```rust\n")
                .unwrap_or_else(|| panic!("language header missing"));
            let body = rest
                .strip_suffix("\n```")
                .unwrap_or_else(|| panic!("pure close missing"));
            recovered.push_str(&unescape_fence_code(body));
            plains.push_str(plain);
        }
        assert_eq!(recovered, code);
        assert_eq!(plains, source);
        assert_eq!(recovered.matches("```word").count(), 1);
        assert_eq!(recovered.matches("SENTINEL_AFTER_FALSE_CLOSE").count(), 1);
    }

    #[test]
    fn owner_terminal_card_quotes_argv_and_formats_timeout() {
        let shown = format!(
            "terminal {}",
            json!({
                "program": "/usr/bin/curl",
                "argv": ["/usr/bin/curl", "https://example.test/a", "it's"],
                "cwd": "src/app",
                "argv_bytes": 123456,
                "stdin_bytes": 99,
                "timeout_ms": 20000,
                "max_output_bytes": 4096,
                "background": false,
                "output": "not included"
            })
        );
        let card = approval_card(&shown, true);
        assert!(card.attach_keyboard);
        assert!(card.text.starts_with("*需要授权 · 执行命令*"));
        assert!(
            card.text
                .contains("'/usr/bin/curl' 'https://example.test/a' 'it'\\\\''s'")
        );
        assert!(card.text.contains("目录：src/app"));
        assert!(card.text.contains("工具超时：20 秒"));
        assert!(card.text.contains("方式：前台"));
        assert!(!card.text.contains("123456"));
        assert!(!card.text.contains("argv_bytes"));
        assert!(!card.text.contains("guardian-approval"));
        let odd = approval_card(
            &format!(
                "terminal {}",
                json!({
                    "program": "printf",
                    "argv": ["printf", "VISIBLE"],
                    "cwd": "",
                    "timeout_ms": 1500,
                    "background": true
                })
            ),
            true,
        );
        assert!(odd.text.contains("工具超时：1500 毫秒"));
        assert!(odd.text.contains("目录：当前工作区"));
        assert!(odd.text.contains("方式：后台"));
    }

    #[test]
    fn terminal_card_zero_timeout_says_unspecified_tool_default() {
        let shown = format!(
            "terminal {}",
            json!({
                "program": "/usr/bin/curl",
                "argv": ["/usr/bin/curl", "https://example.test/a"],
                "cwd": "src/app",
                "timeout_ms": 0,
                "background": false
            })
        );
        let card = approval_card(&shown, true);
        assert!(
            card.text.contains("工具超时：未指定（工具默认）"),
            "{}",
            card.text
        );
        assert!(!card.text.contains("0 秒"), "{}", card.text);
        assert!(!card.text.contains("30000"), "{}", card.text);
        assert!(!card.text.contains("30 秒"), "{}", card.text);
        assert!(
            card.text
                .contains("'/usr/bin/curl' 'https://example.test/a'")
        );
    }

    #[test]
    fn redacted_terminal_and_incomplete_preview_have_no_buttons() {
        let redacted = format!(
            "terminal {}",
            json!({
                "program": "printf",
                "argv": ["printf", "<redacted>"],
                "cwd": "project",
                "timeout_ms": 20000,
                "background": false
            })
        );
        let card = approval_card(&redacted, false);
        assert!(!card.attach_keyboard);
        assert!(card.text.contains("'<redacted>'"));
        assert!(!card.text.contains("OWNER_SECRET"));
        let missing_timeout = format!(
            "terminal {}",
            json!({"program": "printf", "argv": ["printf"], "cwd": "", "background": false})
        );
        assert!(!approval_card(&missing_timeout, true).attach_keyboard);
    }

    #[test]
    fn file_cards_drop_byte_counts_and_raw_json() {
        let shown = format!(
            "write_file {}",
            json!({
                "operation": "replace file",
                "path": "notes.md",
                "content_bytes": 98765,
                "file_content": "withheld"
            })
        );
        let card = approval_card(&shown, false);
        assert!(card.attach_keyboard);
        assert!(card.text.contains("*需要授权 · 写入文件*"));
        assert!(card.text.contains("`notes.md`"));
        assert!(!card.text.contains("98765"));
        assert!(!card.text.contains("content_bytes"));
        assert!(!card.text.contains("file_content"));
    }
}
