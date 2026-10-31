//! Minimal YAML reader for the importer.
//!
//! Covers the subset a Kubernetes manifest and an Envoy bootstrap use: block
//! mappings and sequences, quoted and plain scalars, inline sequences
//! (`["h2", "http/1.1"]`), empty inline maps (`{}`), block scalars (`|`, `>`)
//! and multi-document files (`---`). Anchors, aliases, tags, merge keys and
//! flow mappings with content are **rejected with a message** — the importer
//! must not silently read a manifest it does not understand.

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Value {
    Null,
    Scalar(String),
    Seq(Vec<Value>),
    Map(Vec<(String, Value)>),
}

impl Value {
    pub(super) fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Self::Map(entries) => entries
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    pub(super) fn entries(&self) -> &[(String, Value)] {
        match self {
            Self::Map(entries) => entries,
            _ => &[],
        }
    }

    pub(super) fn items(&self) -> &[Value] {
        match self {
            Self::Seq(items) => items,
            _ => &[],
        }
    }

    pub(super) fn text(&self) -> Option<&str> {
        match self {
            Self::Scalar(text) => Some(text),
            _ => None,
        }
    }
}

struct Lines {
    items: Vec<(usize, String)>,
    pos: usize,
}

impl Lines {
    fn peek(&self) -> Option<&(usize, String)> {
        self.items.get(self.pos)
    }

    fn advance(&mut self) {
        self.pos += 1;
    }
}

/// Parses a document stream.
pub(super) fn documents(text: &str) -> Result<Vec<Value>, String> {
    let mut documents = Vec::new();
    let mut current: Vec<(usize, String)> = Vec::new();
    let mut lines = text.lines().peekable();

    while let Some(raw) = lines.next() {
        let line = strip_comment(raw).trim_end().to_owned();
        let indent = line.len() - line.trim_start().len();
        let content = line.trim_start().to_owned();
        if content.is_empty() {
            continue;
        }
        if content == "---" {
            flush(&mut current, &mut documents)?;
            continue;
        }
        if content == "..." || content.starts_with('%') {
            continue;
        }
        let is_block_scalar = content.ends_with('|')
            || content.ends_with('>')
            || content.ends_with("|-")
            || content.ends_with(">-")
            || content.ends_with("|+")
            || content.ends_with(">+");
        if is_block_scalar {
            let mut scalar = String::new();
            while let Some(next) = lines.peek() {
                let next_line = next.trim_end();
                if next_line.trim().is_empty() {
                    scalar.push('\n');
                    lines.next();
                    continue;
                }
                let next_indent = next_line.len() - next_line.trim_start().len();
                if next_indent <= indent {
                    break;
                }
                scalar.push_str(next_line.trim_start());
                scalar.push('\n');
                lines.next();
            }
            let key = content.trim_end_matches(['|', '>', '-', '+']);
            const BLOCK: char = '\u{1}';
            current.push((indent, format!("{key}{BLOCK}{}", scalar.trim_end())));
            continue;
        }
        current.push((indent, content));
    }
    flush(&mut current, &mut documents)?;
    Ok(documents)
}

fn flush(current: &mut Vec<(usize, String)>, out: &mut Vec<Value>) -> Result<(), String> {
    if current.is_empty() {
        return Ok(());
    }
    let mut lines = Lines {
        items: std::mem::take(current),
        pos: 0,
    };
    let value = parse_block(&mut lines, 0)?;
    out.push(value);
    Ok(())
}

fn strip_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    for (index, ch) in line.char_indices() {
        match quote {
            Some(q) if ch == q => quote = None,
            Some(_) => {}
            None => match ch {
                '"' | '\'' => quote = Some(ch),
                '#' if index == 0
                    || line[..index].ends_with(' ')
                    || line[..index].ends_with('\t') =>
                {
                    return &line[..index];
                }
                _ => {}
            },
        }
    }
    line
}

fn parse_block(lines: &mut Lines, indent: usize) -> Result<Value, String> {
    match lines.peek() {
        None => Ok(Value::Null),
        Some((line_indent, content)) => {
            if *line_indent < indent {
                return Ok(Value::Null);
            }
            if content.starts_with('-') && (content.len() == 1 || content.starts_with("- ")) {
                parse_seq(lines, *line_indent)
            } else {
                parse_map(lines, *line_indent)
            }
        }
    }
}

fn parse_seq(lines: &mut Lines, indent: usize) -> Result<Value, String> {
    let mut items = Vec::new();
    while let Some((line_indent, content)) = lines.peek() {
        if *line_indent < indent {
            break;
        }
        if *line_indent > indent {
            return Err(format!(
                "secuencia: indentación inesperada ({line_indent} > {indent})"
            ));
        }
        if !(content.starts_with('-') && (content.len() == 1 || content.starts_with("- "))) {
            break;
        }
        let item = content[1..].trim_start().to_owned();
        lines.advance();
        if item.is_empty() {
            let next_indent = lines.peek().map(|(i, _)| *i);
            match next_indent {
                Some(next) if next > indent => items.push(parse_block(lines, next)?),
                _ => items.push(Value::Null),
            }
            continue;
        }
        if let Some((key, rest)) = split_key(&item) {
            items.push(Value::Map(item_entries(lines, key, rest, indent)?));
        } else {
            items.push(scalar_value(&item)?);
        }
    }
    Ok(Value::Seq(items))
}

/// Entries of a sequence item written as an inline mapping (`- key: value`),
/// including its nested block and any sibling keys at the same indentation.
fn item_entries(
    lines: &mut Lines,
    key: String,
    rest: String,
    indent: usize,
) -> Result<Vec<(String, Value)>, String> {
    let mut entries = Vec::new();
    if rest.is_empty() {
        match lines.peek().map(|(i, _)| *i) {
            Some(next) if next > indent => {
                entries.push((key, parse_block(lines, next)?));
            }
            _ => entries.push((key, Value::Null)),
        }
    } else {
        entries.push((key, scalar_value(&rest)?));
    }
    // Sibling keys of the item live at any deeper indentation, not only at the
    // one the first nested block used (`load_balancing_weight` after a deeper
    // `endpoint:` map, for instance).
    if let Some(next) = lines.peek().map(|(i, _)| *i).filter(|next| *next > indent)
        && let Value::Map(siblings) = parse_map(lines, next)?
    {
        entries.extend(siblings);
    }
    Ok(entries)
}

fn parse_map(lines: &mut Lines, indent: usize) -> Result<Value, String> {
    let mut entries = Vec::new();
    while let Some((line_indent, content)) = lines.peek() {
        if *line_indent < indent {
            break;
        }
        if *line_indent > indent {
            return Err(format!(
                "mapa: indentación inesperada ({line_indent} > {indent})"
            ));
        }
        if content.starts_with('-') && (content.len() == 1 || content.starts_with("- ")) {
            break;
        }
        let Some((key, rest)) = split_key(content) else {
            return Err(format!("mapa: se esperaba «clave: valor» en «{content}»"));
        };
        lines.advance();
        if rest.is_empty() {
            match lines.peek() {
                Some((next, _)) if *next > indent => {
                    let next = *next;
                    entries.push((key, parse_block(lines, next)?));
                }
                // A sequence may sit at the same indentation as its key:
                //   tls:
                //   - hosts: …
                Some((next, content))
                    if *next == indent && (content.starts_with("- ") || content == "-") =>
                {
                    entries.push((key, parse_seq(lines, indent)?));
                }
                _ => entries.push((key, Value::Null)),
            }
        } else {
            entries.push((key, scalar_value(&rest)?));
        }
    }
    Ok(Value::Map(entries))
}

fn split_key(content: &str) -> Option<(String, String)> {
    let mut quote: Option<char> = None;
    let mut depth = 0i32;
    let iter = content.char_indices().peekable();
    for (index, ch) in iter {
        match quote {
            Some(q) if ch == q => quote = None,
            Some(_) => {}
            None => match ch {
                '"' | '\'' => quote = Some(ch),
                '[' | '{' => depth += 1,
                ']' | '}' => depth -= 1,
                ':' if depth == 0 => {
                    let key = content[..index].trim().trim_matches(['"', '\'']).to_owned();
                    let rest = content[index + 1..].trim_start().to_owned();
                    // `key: value` needs a space or end-of-line after the colon;
                    // `12:30` or `type.googleapis.com/x` are scalars.
                    if rest.is_empty() || content[index + 1..].starts_with(' ') {
                        return Some((key, rest));
                    }
                    if rest.starts_with('[') || rest.starts_with('{') {
                        return Some((key, rest));
                    }
                    return None;
                }
                _ => {}
            },
        }
    }
    None
}

fn scalar_value(raw: &str) -> Result<Value, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(Value::Null);
    }
    if let Some(scalar) = raw.strip_prefix('\u{1}') {
        return Ok(Value::Scalar(scalar.to_owned()));
    }
    if raw == "{}" {
        return Ok(Value::Map(Vec::new()));
    }
    if raw == "[]" {
        return Ok(Value::Seq(Vec::new()));
    }
    if raw.starts_with('[') && raw.ends_with(']') {
        let inner = &raw[1..raw.len() - 1];
        let mut items = Vec::new();
        for part in split_flow(inner) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            items.push(scalar_value(part)?);
        }
        return Ok(Value::Seq(items));
    }
    if raw.starts_with('{') {
        return Err(format!("mapa en línea no soportado: «{raw}»"));
    }
    if raw.starts_with('&') || raw.starts_with('*') || raw.starts_with('!') {
        return Err(format!(
            "anclas, alias y etiquetas YAML no soportados: «{raw}»"
        ));
    }
    if raw.starts_with('"') || raw.starts_with('\'') {
        let quote = raw.chars().next().unwrap_or('"');
        if raw.len() < 2 || !raw.ends_with(quote) {
            return Err(format!("cadena sin cerrar: «{raw}»"));
        }
        return Ok(Value::Scalar(raw[1..raw.len() - 1].to_owned()));
    }
    Ok(Value::Scalar(raw.to_owned()))
}

fn split_flow(inner: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for ch in inner.chars() {
        match quote {
            Some(q) if ch == q => {
                quote = None;
                current.push(ch);
            }
            Some(_) => current.push(ch),
            None => match ch {
                '"' | '\'' => {
                    quote = Some(ch);
                    current.push(ch);
                }
                ',' => {
                    out.push(std::mem::take(&mut current));
                }
                _ => current.push(ch),
            },
        }
    }
    if !current.trim().is_empty() {
        out.push(current);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Value {
        documents(text).expect("must parse").remove(0)
    }

    #[test]
    fn reads_the_shape_of_a_kubernetes_manifest() {
        let doc = parse(
            "apiVersion: v1\nkind: Ingress\nmetadata:\n  name: web\n  annotations:\n    a: \"b\"\nspec:\n  rules:\n  - host: ejemplo.com\n    http:\n      paths:\n      - path: /\n        backend:\n          service:\n            name: svc\n            port:\n              number: 80\n",
        );
        assert_eq!(doc.get("kind").and_then(Value::text), Some("Ingress"));
        assert_eq!(
            doc.get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(Value::text),
            Some("web")
        );
        let rule = &doc
            .get("spec")
            .and_then(|s| s.get("rules"))
            .expect("rules")
            .items()[0];
        assert_eq!(rule.get("host").and_then(Value::text), Some("ejemplo.com"));
        let path = &rule
            .get("http")
            .and_then(|h| h.get("paths"))
            .expect("paths")
            .items()[0];
        assert_eq!(
            path.get("backend")
                .and_then(|b| b.get("service"))
                .and_then(|s| s.get("port"))
                .and_then(|p| p.get("number"))
                .and_then(Value::text),
            Some("80")
        );
    }

    #[test]
    fn inline_sequences_and_block_scalars_are_supported() {
        let doc = parse("alpn: [\"h2\", \"http/1.1\"]\ncode: |\n  linea1\n  linea2\nnext: 1\n");
        assert_eq!(doc.get("alpn").expect("alpn").items().len(), 2);
        assert_eq!(
            doc.get("code").and_then(Value::text),
            Some("linea1\nlinea2")
        );
        assert_eq!(doc.get("next").and_then(Value::text), Some("1"));
    }

    #[test]
    fn documents_are_split_on_the_marker() {
        let docs = documents("a: 1\n---\nb: 2\n").expect("must parse");
        assert_eq!(docs.len(), 2);
        assert_eq!(docs[1].get("b").and_then(Value::text), Some("2"));
    }

    #[test]
    fn unsupported_constructs_are_errors_not_guesses() {
        assert!(documents("a: &anchor valor\n").is_err());
        assert!(documents("a: {x: 1}\n").is_err());
        assert!(documents("a:\n   b: 1\n  c: 2\n").is_err());
    }

    #[test]
    fn colons_inside_values_do_not_split_the_key() {
        let doc = parse("name: type.googleapis.com/envoy\n");
        assert_eq!(
            doc.get("name").and_then(Value::text),
            Some("type.googleapis.com/envoy")
        );
    }
}
