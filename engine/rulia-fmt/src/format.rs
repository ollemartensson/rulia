use crate::ast::{
    Annotation, Args, Binding, FnExpr, Generator, GeneratorKind, HashAlgorithm, Import, InfixExpr,
    Keyword, LetExpr, MapKey, NsMacro, Pattern, Symbol, TaggedValue, Value,
};

pub fn format_value(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, &mut out);
    out
}

fn write_value(value: &Value, out: &mut String) {
    match value {
        Value::Nil => out.push_str("nil"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(v) => out.push_str(&v.to_string()),
        Value::UInt(v) => out.push_str(&format!("{}u", v)),
        Value::BigInt(v) => out.push_str(&format!("{}N", v)),
        Value::Float32(v) => out.push_str(&format!("{}f", v)),
        Value::Float64(v) => {
            let mut rendered = v.to_string();
            if !rendered.contains('.') && !rendered.contains('e') && !rendered.contains('E') {
                rendered.push_str(".0");
            }
            out.push_str(&rendered);
        }
        Value::String(s) => {
            out.push('"');
            out.push_str(&escape_string(s));
            out.push('"');
        }
        Value::Bytes(bytes) => {
            out.push_str("0x[");
            for byte in bytes {
                out.push_str(&format!("{:02x}", byte));
            }
            out.push(']');
        }
        Value::Keyword(kw) => out.push_str(&format_keyword_value(kw)),
        Value::Symbol(sym) => out.push_str(&format_symbol(sym)),
        Value::Vector(items) => {
            out.push('[');
            let mut first = true;
            for item in items {
                if !first {
                    out.push_str(", ");
                }
                first = false;
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Set(items) => {
            out.push_str("Set([");
            let mut ordered: Vec<(String, &Value)> = items
                .iter()
                .map(|item| (canonical_sort_key(item), item))
                .collect();
            ordered.sort_by(|a, b| a.0.cmp(&b.0));
            let mut first = true;
            for (_, item) in ordered {
                if !first {
                    out.push_str(", ");
                }
                first = false;
                write_value(item, out);
            }
            out.push_str("])");
        }
        Value::Map(entries) => {
            out.push('(');
            let mut ordered = ordered_map_entries(entries);
            let mut first = true;
            for (_, key, value) in ordered.drain(..) {
                if !first {
                    out.push_str(", ");
                }
                first = false;
                out.push_str(&format_map_key(key));
                out.push('=');
                write_value(value, out);
            }
            out.push(')');
        }
        Value::Tagged(tagged) => write_tagged(tagged, out),
        Value::Call(call) => write_call(call.name.as_str(), &call.args, out),
        Value::Import(import) => write_import(import, out),
        Value::Generator(generator) => write_generator(generator, out),
        Value::Let(expr) => write_let(expr, out),
        Value::Fn(expr) => write_fn(expr, out),
        Value::Ns(ns) => write_ns(ns, out),
        Value::Infix(expr) => write_infix(expr, out),
        Value::Annotated(annotation) => write_annotation(annotation, out),
    }
}

fn write_tagged(tagged: &TaggedValue, out: &mut String) {
    if tagged.tag.namespace.is_none() && tagged.tag.name == "ref" {
        out.push_str("Ref(");
        if let Value::Vector(items) = &*tagged.value {
            let mut first = true;
            for item in items {
                if !first {
                    out.push_str(", ");
                }
                first = false;
                write_value(item, out);
            }
        } else {
            write_value(&tagged.value, out);
        }
        out.push(')');
        return;
    }

    if symbol_is_simple_pascal(&tagged.tag) {
        let tag_name = if let Some(ns) = &tagged.tag.namespace {
            format!("{}{}", to_pascal_case(ns), to_pascal_case(&tagged.tag.name))
        } else {
            to_pascal_case(&tagged.tag.name)
        };
        out.push_str(&tag_name);
        out.push('(');
        write_value(&tagged.value, out);
        out.push(')');
        return;
    }

    out.push_str("Tagged(\"");
    out.push_str(&escape_string(&tagged.tag.as_str()));
    out.push_str("\", ");
    write_value(&tagged.value, out);
    out.push(')');
}

fn write_call(name: &str, args: &Args, out: &mut String) {
    out.push_str(name);
    out.push('(');
    match args {
        Args::Map(entries) => {
            let mut first = true;
            for (key, value) in entries {
                if !first {
                    out.push_str(", ");
                }
                first = false;
                out.push_str(&format_map_key(key));
                out.push('=');
                write_value(value, out);
            }
        }
        Args::Positional(values) => {
            let mut first = true;
            for value in values {
                if !first {
                    out.push_str(", ");
                }
                first = false;
                write_value(value, out);
            }
        }
    }
    out.push(')');
}

fn write_import(import: &Import, out: &mut String) {
    out.push_str("import ");
    out.push('"');
    out.push_str(&escape_string(&import.path));
    out.push('"');
    if let Some(hash) = &import.hash {
        out.push(' ');
        let alg = match hash.algorithm {
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Blake3 => "blake3",
        };
        out.push_str(alg);
        out.push(':');
        out.push_str(&hash.hex);
    }
}

fn write_generator(generator: &Generator, out: &mut String) {
    match generator.kind {
        GeneratorKind::New => out.push_str("@new("),
        GeneratorKind::Generator => out.push_str("Generator("),
    }
    out.push_str(&format_keyword_value(&generator.keyword));
    out.push(')');
}

fn write_let(expr: &LetExpr, out: &mut String) {
    out.push_str("let ");
    if expr.bindings.len() == 1 {
        write_binding(&expr.bindings[0], out);
    } else {
        out.push('{');
        let mut first = true;
        for binding in &expr.bindings {
            if !first {
                out.push_str("; ");
            }
            first = false;
            write_binding(binding, out);
        }
        out.push('}');
    }
    out.push(' ');
    write_value(&expr.body, out);
}

fn write_binding(binding: &Binding, out: &mut String) {
    write_pattern(&binding.pattern, out);
    out.push('=');
    write_value(&binding.value, out);
}

fn write_pattern(pattern: &Pattern, out: &mut String) {
    match pattern {
        Pattern::Identifier(name) => out.push_str(name),
        Pattern::Tuple(items) => {
            out.push('(');
            write_pattern_items(items, out);
            out.push(')');
        }
        Pattern::Vector(items) => {
            out.push('[');
            write_pattern_items(items, out);
            out.push(']');
        }
    }
}

fn write_pattern_items(items: &[String], out: &mut String) {
    let mut first = true;
    for item in items {
        if !first {
            out.push_str(", ");
        }
        first = false;
        out.push_str(item);
    }
}

fn write_fn(expr: &FnExpr, out: &mut String) {
    out.push_str("fn(");
    let mut first = true;
    for param in &expr.params {
        if !first {
            out.push_str(", ");
        }
        first = false;
        out.push_str(param);
    }
    out.push_str(") => ");
    write_value(&expr.body, out);
}

fn write_ns(ns: &NsMacro, out: &mut String) {
    out.push_str("@ns ");
    out.push_str(&ns.namespace);
    out.push_str(" begin ");
    write_value(&ns.value, out);
    out.push_str(" end");
}

fn write_infix(expr: &InfixExpr, out: &mut String) {
    out.push('(');
    for (idx, item) in expr.items.iter().enumerate() {
        if idx > 0 {
            out.push(' ');
            out.push_str(&expr.operators[idx - 1]);
            out.push(' ');
        }
        write_value(item, out);
    }
    out.push(')');
}

fn write_annotation(annotation: &Annotation, out: &mut String) {
    let (doc_value, other_metadata) = split_doc_metadata(&annotation.metadata);
    if !other_metadata.is_empty() {
        let mut ordered = ordered_metadata_entries(&other_metadata);
        out.push_str("@meta(");
        let mut first = true;
        for (_, key, value) in ordered.drain(..) {
            if !first {
                out.push_str(", ");
            }
            first = false;
            out.push_str(&format_map_key(key));
            out.push_str(" = ");
            write_value(value, out);
        }
        out.push_str(")\n");
    }

    if let Some(doc) = doc_value {
        if doc.contains('\n') {
            let normalized = normalize_multiline_doc(doc);
            out.push_str("\"\"\"\n");
            out.push_str(&normalized);
            if !normalized.ends_with('\n') {
                out.push('\n');
            }
            out.push_str("\"\"\"\n");
        } else {
            out.push('"');
            out.push_str(&escape_string(doc));
            out.push_str("\"\n");
        }
    }

    write_value(&annotation.value, out);
}

fn split_doc_metadata(metadata: &[(MapKey, Value)]) -> (Option<&str>, Vec<(&MapKey, &Value)>) {
    let mut doc_value: Option<&str> = None;
    let mut other = Vec::new();
    for (key, value) in metadata {
        if is_doc_key(key) {
            if let Value::String(s) = value {
                if !s.is_empty() || doc_value.is_none() {
                    doc_value = Some(s);
                }
                continue;
            }
        }
        other.push((key, value));
    }
    (doc_value, other)
}

fn ordered_metadata_entries<'a>(
    entries: &'a [(&'a MapKey, &'a Value)],
) -> Vec<(String, &'a MapKey, &'a Value)> {
    let mut ordered: Vec<(String, &'a MapKey, &'a Value)> = entries
        .iter()
        .map(|(k, v)| (map_key_sort_key(k), *k, *v))
        .collect();
    ordered.sort_by(|a, b| a.0.cmp(&b.0));
    ordered
}

fn ordered_map_entries<'a>(entries: &'a [(MapKey, Value)]) -> Vec<(String, &'a MapKey, &'a Value)> {
    let mut ordered: Vec<(String, &'a MapKey, &'a Value)> = entries
        .iter()
        .map(|(k, v)| (map_key_sort_key(k), k, v))
        .collect();
    ordered.sort_by(|a, b| a.0.cmp(&b.0));
    ordered
}

fn format_map_key(key: &MapKey) -> String {
    match key {
        MapKey::Identifier(name) => name.clone(),
        MapKey::Keyword(kw) => format_keyword_map_key(kw),
        MapKey::String(s) => format_string_value(s),
    }
}

fn map_key_sort_key(key: &MapKey) -> String {
    match key {
        MapKey::Identifier(name) => format_keyword_value(&keyword_from_identifier(name)),
        MapKey::Keyword(kw) => format_keyword_value(kw),
        MapKey::String(s) => format_string_value(s),
    }
}

fn format_keyword_value(kw: &Keyword) -> String {
    if keyword_is_simple_sugar(kw) {
        let mut out = String::from(":");
        if let Some(ns) = &kw.namespace {
            out.push_str(ns);
            out.push('_');
        }
        out.push_str(&kw.name);
        out
    } else {
        format!("Keyword(\"{}\")", escape_string(&kw.as_str()))
    }
}

fn format_keyword_map_key(kw: &Keyword) -> String {
    if keyword_is_simple_sugar(kw) {
        if let Some(ns) = &kw.namespace {
            format!("{}_{}", ns, kw.name.as_str())
        } else {
            kw.name.clone()
        }
    } else {
        format!("Keyword(\"{}\")", escape_string(&kw.as_str()))
    }
}

fn keyword_from_identifier(ident: &str) -> Keyword {
    if let Some((ns, name)) = ident.split_once('_') {
        Keyword {
            namespace: Some(ns.to_string()),
            name: name.to_string(),
        }
    } else {
        Keyword {
            namespace: None,
            name: ident.to_string(),
        }
    }
}

fn keyword_is_simple_sugar(kw: &Keyword) -> bool {
    match kw.namespace.as_deref() {
        None => true,
        Some(ns) => !ns.contains('_'),
    }
}

fn is_doc_key(key: &MapKey) -> bool {
    match key {
        MapKey::Identifier(name) => name == "doc",
        MapKey::Keyword(kw) => kw.namespace.is_none() && kw.name == "doc",
        MapKey::String(_) => false,
    }
}

fn format_symbol(sym: &Symbol) -> String {
    if sym.namespace.is_none() && sym.name == "_" {
        return "_".to_string();
    }
    if sym.namespace.is_none() && sym.name.starts_with('?') {
        return format!("@{}", sym.name);
    }
    if sym.namespace.is_some() {
        return format!("Symbol(\"{}\")", escape_string(&sym.as_str()));
    }
    format!("'{}", sym.name)
}

fn symbol_is_simple_pascal(sym: &Symbol) -> bool {
    if sym.namespace.is_none()
        && sym
            .name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return true;
    }
    if let Some(ns) = &sym.namespace {
        let ns_ok = ns
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
        let name_ok = sym
            .name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        return ns_ok && name_ok;
    }
    false
}

fn to_pascal_case(s: &str) -> String {
    let mut result = String::new();
    let mut capitalize_next = true;
    for ch in s.chars() {
        if ch == '_' || ch == '-' {
            capitalize_next = true;
        } else if capitalize_next {
            result.push(ch.to_ascii_uppercase());
            capitalize_next = false;
        } else {
            result.push(ch);
        }
    }
    result
}

fn escape_string(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '$' => out.push_str("\\$"),
            _ => out.push(ch),
        }
    }
    out
}

fn normalize_multiline_doc(doc: &str) -> String {
    let mut text = doc.to_string();
    if text.starts_with("\r\n") {
        text.drain(..2);
    } else if text.starts_with('\n') {
        text.drain(..1);
    }
    if text.ends_with('\n') {
        text.pop();
        if text.ends_with('\r') {
            text.pop();
        }
    }
    text
}

fn format_string_value(s: &str) -> String {
    format!("\"{}\"", escape_string(s))
}

fn canonical_sort_key(value: &Value) -> String {
    format_value(value)
}

impl Keyword {
    fn as_str(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("{}/{}", ns, self.name),
            None => self.name.clone(),
        }
    }
}

impl Symbol {
    fn as_str(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("{}/{}", ns, self.name),
            None => self.name.clone(),
        }
    }
}
