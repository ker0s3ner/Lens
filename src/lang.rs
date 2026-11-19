//! Re-spells the decompiler's C-like output in another language's syntax.
//!
//! This is a rewrite of the same logic, not recovery of the original source: a program written
//! in Rust and compiled to machine code does not contain its Rust any more, so what can be
//! shown is what the machine code does, written the way the chosen language would write it.

use crate::decomp::{DLine, Decompiled};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lang {
    C,
    Python,
    Rust,
    Go,
    JavaScript,
}

impl Lang {
    pub fn all() -> [Lang; 5] {
        [Lang::C, Lang::Python, Lang::Rust, Lang::Go, Lang::JavaScript]
    }
    pub fn label(self) -> &'static str {
        match self {
            Lang::C => "C",
            Lang::Python => "Python",
            Lang::Rust => "Rust",
            Lang::Go => "Go",
            Lang::JavaScript => "JavaScript",
        }
    }
    pub fn ext(self) -> &'static str {
        match self {
            Lang::C => "c",
            Lang::Python => "py",
            Lang::Rust => "rs",
            Lang::Go => "go",
            Lang::JavaScript => "js",
        }
    }
    pub fn comment(self) -> &'static str {
        match self {
            Lang::Python => "#",
            _ => "//",
        }
    }
    pub fn index(self) -> u8 {
        Lang::all().iter().position(|l| *l == self).unwrap_or(0) as u8
    }
}

const TYPES: [&str; 11] =
    ["int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t", "float", "double", "__m128"];

fn is_type(w: &str) -> bool {
    TYPES.contains(&w)
}

fn ty(t: &str, lang: Lang) -> &'static str {
    let i = TYPES.iter().position(|x| *x == t).unwrap_or(3);
    const RUST: [&str; 11] = ["i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64", "f32", "f64", "u128"];
    const GO: [&str; 11] = ["int8", "int16", "int32", "int64", "uint8", "uint16", "uint32", "uint64", "float32", "float64", "[16]byte"];
    const JS: [&str; 11] = ["i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64", "f32", "f64", "u128"];
    match lang {
        Lang::Rust => RUST[i],
        Lang::Go => GO[i],
        Lang::JavaScript => JS[i],
        _ => RUST[i],
    }
}

/// End (exclusive) of the operand that starts at `i`: prefix operators, then a name, number,
/// string or parenthesised group, then any call parentheses.
fn operand_end(s: &[char], mut i: usize) -> usize {
    while i < s.len() && matches!(s[i], '-' | '~' | '!' | '&') {
        i += 1;
    }
    // chained casts / derefs such as (uint8_t)*(uint32_t*)x
    if i < s.len() && s[i] == '*' {
        i += 1;
    }
    if i >= s.len() {
        return i;
    }
    let group = |s: &[char], mut j: usize| -> usize {
        let mut depth = 0;
        while j < s.len() {
            match s[j] {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return j + 1;
                    }
                }
                '"' => {
                    j += 1;
                    while j < s.len() && s[j] != '"' {
                        if s[j] == '\\' {
                            j += 1;
                        }
                        j += 1;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        s.len()
    };
    if s[i] == '(' {
        // a cast such as (uint8_t)x: the operand continues after the type
        let e = group(s, i);
        let inner: String = s[i + 1..e.saturating_sub(1).max(i + 1)].iter().collect();
        if is_type(inner.trim_end_matches('*')) && e < s.len() {
            return operand_end(s, e);
        }
        i = e;
    } else if s[i] == '"' {
        i += 1;
        while i < s.len() && s[i] != '"' {
            if s[i] == '\\' {
                i += 1;
            }
            i += 1;
        }
        i = (i + 1).min(s.len());
    } else {
        while i < s.len() && (s[i].is_alphanumeric() || matches!(s[i], '_' | '.' | '$' | '@' | '?' | ':' | '<' | '>' | '~')) {
            // stop at `::` only if followed by nothing sensible
            i += 1;
        }
    }
    while i < s.len() && s[i] == '(' {
        i = group(s, i);
    }
    i
}

fn type_at(s: &[char], i: usize, ptr: bool) -> Option<(String, usize)> {
    let mut j = i;
    while j < s.len() && (s[j].is_alphanumeric() || s[j] == '_') {
        j += 1;
    }
    let t: String = s[i..j].iter().collect();
    if !is_type(&t) {
        return None;
    }
    if ptr {
        if s.get(j) == Some(&'*') && s.get(j + 1) == Some(&')') {
            return Some((t, j + 2));
        }
        None
    } else if s.get(j) == Some(&')') {
        Some((t, j + 1))
    } else {
        None
    }
}

fn read_mem(t: &str, p: &str, lang: Lang) -> String {
    let short = ty(t, Lang::Rust);
    match lang {
        Lang::Python => format!("read_{short}({p})"),
        Lang::Rust => format!("unsafe {{ *({p} as *const {short}) }}"),
        Lang::Go => format!("*(*{})(unsafe.Pointer(uintptr({p})))", ty(t, Lang::Go)),
        Lang::JavaScript => format!("mem.{short}({p})"),
        Lang::C => format!("*({t}*){p}"),
    }
}

fn write_mem(t: &str, p: &str, v: &str, lang: Lang) -> String {
    let short = ty(t, Lang::Rust);
    match lang {
        Lang::Python => format!("write_{short}({p}, {v})"),
        Lang::Rust => format!("unsafe {{ *({p} as *mut {short}) = {v}; }}"),
        Lang::Go => format!("*(*{})(unsafe.Pointer(uintptr({p}))) = {v}", ty(t, Lang::Go)),
        Lang::JavaScript => format!("mem.set_{short}({p}, {v});"),
        Lang::C => format!("*({t}*){p} = {v};"),
    }
}

fn cast(t: &str, x: &str, lang: Lang) -> String {
    let short = ty(t, Lang::Rust);
    let unsigned = t.starts_with('u');
    let bits: u32 = t.trim_start_matches('u').trim_start_matches("int").trim_end_matches("_t").parse().unwrap_or(64);
    match lang {
        Lang::Python => match t {
            "float" | "double" => format!("float({x})"),
            _ if unsigned && bits < 64 => format!("({x} & 0x{:X})", (1u64 << bits) - 1),
            _ if unsigned => format!("({x} & 0xFFFFFFFFFFFFFFFF)"),
            _ => format!("to_{short}({x})"),
        },
        Lang::Rust => format!("({x} as {short})"),
        Lang::Go => format!("{}({x})", ty(t, Lang::Go)),
        Lang::JavaScript => match t {
            "uint8_t" => format!("({x} & 0xFF)"),
            "uint16_t" => format!("({x} & 0xFFFF)"),
            "uint32_t" => format!("({x} >>> 0)"),
            "int32_t" | "int16_t" | "int8_t" => format!("({x} | 0)"),
            "float" | "double" => format!("Number({x})"),
            _ => x.to_string(),
        },
        Lang::C => format!("({t}){x}"),
    }
}

fn conv(src: &str, lang: Lang) -> String {
    if lang == Lang::C {
        return src.to_string();
    }
    let s: Vec<char> = src.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c == '"' {
            let st = i;
            i += 1;
            while i < s.len() && s[i] != '"' {
                if s[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            i = (i + 1).min(s.len());
            out.extend(&s[st..i]);
            continue;
        }
        // *(type*)operand
        if c == '*' && s.get(i + 1) == Some(&'(') {
            if let Some((t, after)) = type_at(&s, i + 2, true) {
                let e = operand_end(&s, after);
                let inner: String = s[after..e].iter().collect();
                out.push_str(&read_mem(&t, &conv(&inner, lang), lang));
                i = e;
                continue;
            }
        }
        // (type)operand
        if c == '(' {
            if let Some((t, after)) = type_at(&s, i + 1, false) {
                let e = operand_end(&s, after);
                let inner: String = s[after..e].iter().collect();
                out.push_str(&cast(&t, &conv(&inner, lang), lang));
                i = e;
                continue;
            }
        }
        // unary &name
        if c == '&' && s.get(i + 1).map(|n| n.is_alphabetic() || *n == '_').unwrap_or(false) && (i == 0 || !(s[i - 1].is_alphanumeric() || s[i - 1] == ')')) {
            let e = operand_end(&s, i + 1);
            let name: String = s[i + 1..e].iter().collect();
            out.push_str(&match lang {
                Lang::Rust => format!("core::ptr::addr_of!({name}) as usize"),
                Lang::Go => format!("uintptr(unsafe.Pointer(&{name}))"),
                _ => format!("addr_of({name})"),
            });
            i = e;
            continue;
        }
        if lang == Lang::Python {
            if c == '&' && s.get(i + 1) == Some(&'&') {
                out.push_str("and");
                i += 2;
                continue;
            }
            if c == '|' && s.get(i + 1) == Some(&'|') {
                out.push_str("or");
                i += 2;
                continue;
            }
            if c == '!' && s.get(i + 1) != Some(&'=') {
                out.push_str("not ");
                i += 1;
                continue;
            }
        }
        if lang == Lang::JavaScript {
            if c == '=' && s.get(i + 1) == Some(&'=') {
                out.push_str("===");
                i += 2;
                continue;
            }
            if c == '!' && s.get(i + 1) == Some(&'=') {
                out.push_str("!==");
                i += 2;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

fn strip_parens(c: &str) -> String {
    let t = c.trim();
    if t.starts_with('(') && t.ends_with(')') {
        // only if the first paren closes at the very end
        let mut depth = 0;
        for (k, ch) in t.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 && k != t.len() - 1 {
                        return t.to_string();
                    }
                }
                _ => {}
            }
        }
        return t[1..t.len() - 1].to_string();
    }
    t.to_string()
}

/// "if (cond) rest" → (cond, rest)
fn split_if(t: &str) -> Option<(String, String)> {
    let r = t.strip_prefix("if (")?;
    let mut depth = 1;
    for (k, ch) in r.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some((r[..k].to_string(), r[k + 1..].trim().to_string()));
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_decl(t: &str) -> Option<(String, Vec<String>)> {
    let t = t.strip_suffix(';')?;
    let (ty, rest) = t.split_once(' ')?;
    if !is_type(ty) || rest.contains('=') || rest.contains('(') {
        return None;
    }
    Some((ty.to_string(), rest.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()))
}

fn param_list(p: &str) -> Vec<(String, String)> {
    if p.trim() == "void" || p.trim().is_empty() {
        return vec![];
    }
    p.split(',')
        .filter_map(|x| {
            let x = x.trim();
            let (t, n) = x.split_once(' ')?;
            Some((t.to_string(), n.to_string()))
        })
        .collect()
}

pub fn render(d: &Decompiled, lang: Lang) -> Vec<DLine> {
    if lang == Lang::C {
        return d.lines.clone();
    }
    let mut out: Vec<DLine> = vec![];
    let cm = lang.comment();
    let braces = lang != Lang::Python;
    // closers still waiting: for do-while bodies
    let mut kinds: Vec<(usize, char)> = vec![]; // (indent, 'd' = do-while, 'o' = other)
    let mut pending_open: Option<usize> = None; // python: indent of the last block opener
    let mut ret_void = true;
    for l in &d.lines {
        if l.text.starts_with("return ") {
            ret_void = false;
        }
    }
    let mut sig_done = false;
    let mut idx = 0;
    while idx < d.lines.len() {
        let l = &d.lines[idx];
        idx += 1;
        let t = l.text.trim_end();
        let ind = l.indent;
        let mut push = |out: &mut Vec<DLine>, pending: &mut Option<usize>, indent: usize, text: String| {
            if let Some(oi) = *pending {
                if indent <= oi && lang == Lang::Python {
                    out.push(DLine { text: "pass".into(), addr: l.addr, indent: oi + 1 });
                }
                *pending = None;
            }
            out.push(DLine { text, addr: l.addr, indent });
        };
        if t.is_empty() {
            out.push(DLine { text: String::new(), addr: l.addr, indent: ind });
            continue;
        }
        if let Some(c) = t.strip_prefix("//") {
            push(&mut out, &mut pending_open, ind, format!("{cm}{c}"));
            continue;
        }
        // function signature + opening brace
        if !sig_done && ind == 0 && t.contains('(') && !t.starts_with('{') {
            sig_done = true;
            let lp = t.find('(').unwrap();
            let rp = t.rfind(')').unwrap_or(t.len() - 1);
            let head = &t[..lp];
            let (_rt, name) = head.split_once(' ').unwrap_or(("void", head));
            let ps = param_list(&t[lp + 1..rp]);
            let rtype = if head.starts_with("void ") { None } else { head.split_once(' ').map(|x| x.0.to_string()) };
            let line = match lang {
                Lang::Python => format!("def {name}({}):", ps.iter().map(|p| p.1.clone()).collect::<Vec<_>>().join(", ")),
                Lang::Rust => format!(
                    "fn {name}({}){} {{",
                    ps.iter().map(|p| format!("{}: {}", p.1, ty(&p.0, lang))).collect::<Vec<_>>().join(", "),
                    rtype.as_ref().map(|r| format!(" -> {}", ty(r, lang))).unwrap_or_default()
                ),
                Lang::Go => format!(
                    "func {name}({}){} {{",
                    ps.iter().map(|p| format!("{} {}", p.1, ty(&p.0, lang))).collect::<Vec<_>>().join(", "),
                    rtype.as_ref().map(|r| format!(" {}", ty(r, lang))).unwrap_or_default()
                ),
                _ => format!("function {name}({}) {{", ps.iter().map(|p| p.1.clone()).collect::<Vec<_>>().join(", ")),
            };
            push(&mut out, &mut pending_open, 0, line);
            if lang == Lang::Python {
                pending_open = Some(0);
            }
            // skip the "{" line
            if d.lines.get(idx).map(|x| x.text == "{").unwrap_or(false) {
                idx += 1;
            }
            continue;
        }
        if ind == 0 && t == "}" {
            if braces {
                push(&mut out, &mut pending_open, 0, "}".into());
            }
            continue;
        }
        // declarations
        if let Some((tn, names)) = parse_decl(t) {
            match lang {
                Lang::Python => {}
                Lang::Rust => {
                    for n in names {
                        push(&mut out, &mut pending_open, ind, format!("let mut {n}: {} = 0;", ty(&tn, lang)));
                    }
                }
                Lang::Go => {
                    for n in names {
                        push(&mut out, &mut pending_open, ind, format!("var {n} {}", ty(&tn, lang)));
                    }
                }
                _ => push(&mut out, &mut pending_open, ind, format!("let {};", names.join(", "))),
            }
            continue;
        }
        // labels
        if t.starts_with("L_") && t.ends_with(':') {
            let text = match lang {
                Lang::Go => t.to_string(),
                _ => format!("{cm} {t}"),
            };
            push(&mut out, &mut pending_open, ind, text);
            continue;
        }
        let goto_text = |lbl: &str| -> String {
            match lang {
                Lang::Go => format!("goto {lbl}"),
                Lang::Python => format!("pass  # goto {lbl}"),
                _ => format!("/* goto {lbl} */"),
            }
        };
        if let Some(r) = t.strip_prefix("goto *") {
            push(&mut out, &mut pending_open, ind, format!("{cm} indirect jump: {}", r.trim_end_matches(';')));
            continue;
        }
        if let Some(r) = t.strip_prefix("goto ") {
            let lbl = r.trim_end_matches(';').to_string();
            push(&mut out, &mut pending_open, ind, goto_text(&lbl));
            continue;
        }
        // structure
        if t == "do {" {
            kinds.push((ind, 'd'));
            let (text, open) = match lang {
                Lang::Python => ("while True:".to_string(), true),
                Lang::Rust => ("loop {".to_string(), false),
                Lang::Go => ("for {".to_string(), false),
                _ => ("do {".to_string(), false),
            };
            push(&mut out, &mut pending_open, ind, text);
            if open {
                pending_open = Some(ind);
            }
            continue;
        }
        if let Some(rest) = t.strip_prefix("} while (") {
            let cond = conv(&strip_parens(&format!("({}", rest.trim_end_matches(';'))), lang);
            kinds.pop();
            match lang {
                Lang::Python => push(&mut out, &mut pending_open, ind + 1, format!("if not ({cond}): break")),
                Lang::Rust => {
                    push(&mut out, &mut pending_open, ind + 1, format!("if !({cond}) {{ break; }}"));
                    push(&mut out, &mut pending_open, ind, "}".into());
                }
                Lang::Go => {
                    push(&mut out, &mut pending_open, ind + 1, format!("if !({cond}) {{ break }}"));
                    push(&mut out, &mut pending_open, ind, "}".into());
                }
                _ => push(&mut out, &mut pending_open, ind, format!("}} while ({cond});")),
            }
            continue;
        }
        if t == "} else {" {
            match lang {
                Lang::Python => {
                    push(&mut out, &mut pending_open, ind, "else:".into());
                    pending_open = Some(ind);
                }
                _ => push(&mut out, &mut pending_open, ind, "} else {".into()),
            }
            continue;
        }
        if t == "}" {
            if kinds.last().map(|k| k.0 == ind).unwrap_or(false) {
                kinds.pop();
            }
            if braces {
                push(&mut out, &mut pending_open, ind, "}".into());
            } else if let Some(oi) = pending_open.take() {
                // an empty python block still needs a body
                out.push(DLine { text: "pass".into(), addr: l.addr, indent: oi + 1 });
            }
            continue;
        }
        if t.starts_with("while (") && t.ends_with(") {") {
            let c = &t[7..t.len() - 3];
            let cond = conv(c.trim(), lang);
            let text = match (lang, c.trim()) {
                (Lang::Python, "1") => "while True:".to_string(),
                (Lang::Python, _) => format!("while {cond}:"),
                (Lang::Rust, "1") => "loop {".to_string(),
                (Lang::Rust, _) => format!("while {cond} {{"),
                (Lang::Go, "1") => "for {".to_string(),
                (Lang::Go, _) => format!("for {cond} {{"),
                (_, "1") => "while (true) {".to_string(),
                _ => format!("while ({cond}) {{"),
            };
            kinds.push((ind, 'o'));
            push(&mut out, &mut pending_open, ind, text);
            if lang == Lang::Python {
                pending_open = Some(ind);
            }
            continue;
        }
        if let Some((c, rest)) = split_if(t) {
            let cond = conv(&c, lang);
            if rest == "{" {
                let text = match lang {
                    Lang::Python => format!("if {cond}:"),
                    Lang::Rust | Lang::Go => format!("if {cond} {{"),
                    _ => format!("if ({cond}) {{"),
                };
                kinds.push((ind, 'o'));
                push(&mut out, &mut pending_open, ind, text);
                if lang == Lang::Python {
                    pending_open = Some(ind);
                }
                continue;
            }
            // one-line: if (c) break; / continue; / goto L;
            let action = rest.trim_end_matches(';');
            let act = if let Some(l) = action.strip_prefix("goto ") {
                goto_text(l)
            } else {
                match lang {
                    Lang::Go => action.to_string(),
                    _ => format!("{action};"),
                }
            };
            let text = match lang {
                Lang::Python => format!("if {cond}: {}", act.trim_end_matches(';')),
                Lang::Rust => format!("if {cond} {{ {act} }}"),
                Lang::Go => format!("if {cond} {{ {act} }}"),
                _ => format!("if ({cond}) {{ {act} }}"),
            };
            push(&mut out, &mut pending_open, ind, text);
            continue;
        }
        // plain statements
        let body = t.trim_end_matches(';');
        let semi = if matches!(lang, Lang::Rust | Lang::JavaScript) { ";" } else { "" };
        // store through a pointer
        let chars: Vec<char> = body.chars().collect();
        if chars.first() == Some(&'*') && chars.get(1) == Some(&'(') {
            if let Some((tn, after)) = type_at(&chars, 2, true) {
                let e = operand_end(&chars, after);
                let rest: String = chars[e..].iter().collect();
                if let Some(v) = rest.trim_start().strip_prefix("= ") {
                    let p: String = chars[after..e].iter().collect();
                    let text = write_mem(&tn, &conv(&p, lang), &conv(v, lang), lang);
                    let text = if matches!(lang, Lang::Python | Lang::Go) { text.trim_end_matches(';').to_string() } else { text };
                    push(&mut out, &mut pending_open, ind, text);
                    continue;
                }
            }
        }
        let mut text = conv(body, lang);
        if let Some(r) = text.strip_prefix("return ") {
            if lang == Lang::Python {
                text = format!("return {r}");
            }
        }
        if body == "return" && !ret_void {
            text = "return 0".into();
        }
        push(&mut out, &mut pending_open, ind, format!("{text}{semi}"));
    }
    if lang == Lang::Python {
        // a trailing empty block
        if let Some(oi) = pending_open {
            out.push(DLine { text: "pass".into(), addr: 0, indent: oi + 1 });
        }
    }
    out
}

pub fn render_text(lines: &[DLine]) -> String {
    let mut s = String::new();
    for l in lines {
        s.push_str(&"    ".repeat(l.indent));
        s.push_str(&l.text);
        s.push('\n');
    }
    s
}

/// What a person should know about the chosen language.
pub fn caveat(lang: Lang) -> &'static str {
    match lang {
        Lang::C => "Pseudo-C lifted from machine code. Read it next to the listing; it is not compilable source.",
        Lang::Python => "Same logic written in Python syntax. Memory helpers (read_u32, write_u32, addr_of, to_i32) are placeholders you would supply.",
        Lang::Rust => "Same logic written in Rust syntax. Raw memory access is wrapped in unsafe blocks; it will not compile as is.",
        Lang::Go => "Same logic written in Go syntax. Pointer access goes through unsafe.Pointer; unused variables must be trimmed before it compiles.",
        Lang::JavaScript => "Same logic written in JavaScript syntax. mem.* and addr_of are placeholders for a memory object you would supply.",
    }
}
