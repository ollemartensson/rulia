use num_bigint::BigInt;
use tree_sitter::{Node, Parser};

use crate::ast::{
    Annotation, Args, Binding, Call, FnExpr, Generator, GeneratorKind, HashAlgorithm, HashSpec,
    Import, InfixExpr, Keyword, LetExpr, MapKey, NsMacro, Pattern, Symbol, TaggedValue, Value,
};
use crate::error::{ErrorCode, FormatError};

pub fn parse_value(source: &str) -> Result<Value, FormatError> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rulia::language())
        .map_err(|_| FormatError::new(ErrorCode::Parse, "failed to load grammar", None))?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| FormatError::new(ErrorCode::Parse, "parse failed", None))?;
    let root = tree.root_node();
    if root.has_error() {
        if let Some(err) = first_error(root) {
            return Err(FormatError::new(
                ErrorCode::Parse,
                "parse error",
                Some(err.start_byte()),
            ));
        }
        return Err(FormatError::new(ErrorCode::Parse, "parse error", None));
    }

    let value_node = root
        .named_child(0)
        .ok_or_else(|| FormatError::new(ErrorCode::Parse, "expected value", None))?;
    let parser = AstParser { source };
    parser.parse_value(value_node)
}

fn first_error(node: Node) -> Option<Node> {
    if node.is_error() || node.is_missing() {
        return Some(node);
    }
    let mut cursor = node.walk();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.is_error() || current.is_missing() {
            return Some(current);
        }
        cursor.reset(current);
        for child in current.children(&mut cursor) {
            stack.push(child);
        }
    }
    None
}

struct AstParser<'a> {
    source: &'a str,
}

impl<'a> AstParser<'a> {
    fn parse_value(&self, node: Node) -> Result<Value, FormatError> {
        let node = self.unwrap_value(node);
        match node.kind() {
            "nil" => Ok(Value::Nil),
            "boolean" => self.parse_boolean(node),
            "int" => self.parse_int(node),
            "uint" => self.parse_uint(node),
            "bigint" => self.parse_bigint(node),
            "float32" => self.parse_float32(node),
            "float64" => self.parse_float64(node),
            "bytes" => self.parse_bytes(node),
            "string" | "double_string" | "triple_string" => {
                let s = self.parse_string(node)?;
                Ok(Value::String(s))
            }
            "keyword" => self.parse_keyword(node).map(Value::Keyword),
            "symbol" => self.parse_symbol(node).map(Value::Symbol),
            "vector" => self.parse_vector(node),
            "set" => self.parse_set(node),
            "map" => self.parse_map(node),
            "tagged" => self.parse_tagged(node),
            "call" => self.parse_call(node),
            "import_stmt" => self.parse_import(node),
            "generator" => self.parse_generator(node),
            "let_expr" => self.parse_let(node),
            "fn_expr" => self.parse_fn(node),
            "ns_macro" => self.parse_ns(node),
            "infix_expr" => self.parse_infix(node),
            "annotated" => self.parse_annotated(node),
            other => Err(FormatError::new(
                ErrorCode::Unsupported,
                format!("unsupported node '{other}'"),
                Some(node.start_byte()),
            )),
        }
    }

    fn unwrap_value<'b>(&self, mut node: Node<'b>) -> Node<'b> {
        loop {
            let kind = node.kind();
            if kind == "value" || kind == "number" || kind == "string" {
                if let Some(child) = node.named_child(0) {
                    node = child;
                    continue;
                }
            }
            return node;
        }
    }

    fn parse_boolean(&self, node: Node) -> Result<Value, FormatError> {
        let text = self.node_text(node)?;
        match text {
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            _ => Err(FormatError::new(
                ErrorCode::Parse,
                "invalid boolean",
                Some(node.start_byte()),
            )),
        }
    }

    fn parse_int(&self, node: Node) -> Result<Value, FormatError> {
        let text = self.node_text(node)?;
        let value = text.parse::<i64>().map_err(|_| {
            FormatError::new(
                ErrorCode::InvalidNumber,
                "invalid int",
                Some(node.start_byte()),
            )
        })?;
        Ok(Value::Int(value))
    }

    fn parse_uint(&self, node: Node) -> Result<Value, FormatError> {
        let text = self.node_text(node)?;
        let raw = text.trim_end_matches('u');
        let value = raw.parse::<u64>().map_err(|_| {
            FormatError::new(
                ErrorCode::InvalidNumber,
                "invalid uint",
                Some(node.start_byte()),
            )
        })?;
        Ok(Value::UInt(value))
    }

    fn parse_bigint(&self, node: Node) -> Result<Value, FormatError> {
        let text = self.node_text(node)?;
        let raw = text.trim_end_matches('N');
        let value = raw.parse::<BigInt>().map_err(|_| {
            FormatError::new(
                ErrorCode::InvalidNumber,
                "invalid bigint",
                Some(node.start_byte()),
            )
        })?;
        Ok(Value::BigInt(value))
    }

    fn parse_float32(&self, node: Node) -> Result<Value, FormatError> {
        let text = self.node_text(node)?;
        let raw = text.trim_end_matches('f');
        let value = raw.parse::<f32>().map_err(|_| {
            FormatError::new(
                ErrorCode::InvalidNumber,
                "invalid float32",
                Some(node.start_byte()),
            )
        })?;
        if !value.is_finite() {
            return Err(FormatError::new(
                ErrorCode::InvalidNumber,
                "non-finite float32",
                Some(node.start_byte()),
            ));
        }
        Ok(Value::Float32(value))
    }

    fn parse_float64(&self, node: Node) -> Result<Value, FormatError> {
        let text = self.node_text(node)?;
        let value = text.parse::<f64>().map_err(|_| {
            FormatError::new(
                ErrorCode::InvalidNumber,
                "invalid float64",
                Some(node.start_byte()),
            )
        })?;
        if !value.is_finite() {
            return Err(FormatError::new(
                ErrorCode::InvalidNumber,
                "non-finite float64",
                Some(node.start_byte()),
            ));
        }
        Ok(Value::Float64(value))
    }

    fn parse_bytes(&self, node: Node) -> Result<Value, FormatError> {
        let text = self.node_text(node)?;
        let inner = text
            .strip_prefix("0x[")
            .and_then(|s| s.strip_suffix(']'))
            .ok_or_else(|| {
                FormatError::new(
                    ErrorCode::InvalidBytes,
                    "invalid bytes",
                    Some(node.start_byte()),
                )
            })?;
        if inner.len() % 2 != 0 {
            return Err(FormatError::new(
                ErrorCode::InvalidBytes,
                "invalid bytes",
                Some(node.start_byte()),
            ));
        }
        let mut bytes = Vec::with_capacity(inner.len() / 2);
        let mut idx = 0;
        while idx < inner.len() {
            let chunk = &inner[idx..idx + 2];
            let value = u8::from_str_radix(chunk, 16).map_err(|_| {
                FormatError::new(
                    ErrorCode::InvalidBytes,
                    "invalid bytes",
                    Some(node.start_byte()),
                )
            })?;
            bytes.push(value);
            idx += 2;
        }
        Ok(Value::Bytes(bytes))
    }

    fn parse_string(&self, node: Node) -> Result<String, FormatError> {
        let node = self.unwrap_value(node);
        match node.kind() {
            "double_string" => self.parse_double_string(node),
            "triple_string" => self.parse_triple_string(node),
            "string" => {
                let child = node.named_child(0).ok_or_else(|| {
                    FormatError::new(ErrorCode::InvalidString, "empty string", None)
                })?;
                self.parse_string(child)
            }
            _ => Err(FormatError::new(
                ErrorCode::InvalidString,
                "invalid string",
                Some(node.start_byte()),
            )),
        }
    }

    fn parse_double_string(&self, node: Node) -> Result<String, FormatError> {
        let text = self.node_text(node)?;
        let inner = text
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .ok_or_else(|| {
                FormatError::new(
                    ErrorCode::InvalidString,
                    "invalid string",
                    Some(node.start_byte()),
                )
            })?;
        let mut out = String::new();
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                let next = chars.next().ok_or_else(|| {
                    FormatError::new(
                        ErrorCode::InvalidString,
                        "invalid escape",
                        Some(node.start_byte()),
                    )
                })?;
                match next {
                    '\\' => out.push('\\'),
                    '"' => out.push('"'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    '$' => out.push('$'),
                    _ => {
                        return Err(FormatError::new(
                            ErrorCode::InvalidString,
                            "invalid escape",
                            Some(node.start_byte()),
                        ))
                    }
                }
            } else {
                out.push(ch);
            }
        }
        Ok(out)
    }

    fn parse_triple_string(&self, node: Node) -> Result<String, FormatError> {
        let text = self.node_text(node)?;
        if !text.starts_with("\"\"\"") || !text.ends_with("\"\"\"") {
            return Err(FormatError::new(
                ErrorCode::InvalidString,
                "invalid triple string",
                Some(node.start_byte()),
            ));
        }
        let inner = &text[3..text.len() - 3];
        Ok(inner.to_string())
    }

    fn parse_keyword(&self, node: Node) -> Result<Keyword, FormatError> {
        let child = node.named_child(0).ok_or_else(|| {
            FormatError::new(ErrorCode::Parse, "invalid keyword", Some(node.start_byte()))
        })?;
        match child.kind() {
            "identifier" => {
                let ident = self.node_text(child)?;
                Ok(keyword_from_identifier(ident))
            }
            "string" | "double_string" | "triple_string" => {
                let s = self.parse_string(child)?;
                Ok(keyword_from_string(&s))
            }
            _ => Err(FormatError::new(
                ErrorCode::Parse,
                "invalid keyword",
                Some(node.start_byte()),
            )),
        }
    }

    fn parse_symbol(&self, node: Node) -> Result<Symbol, FormatError> {
        let text = self.node_text(node)?;
        if text == "_" {
            return Ok(Symbol {
                namespace: None,
                name: "_".to_string(),
            });
        }
        if let Some(child) = node.named_child(0) {
            if child.kind() == "string"
                || child.kind() == "double_string"
                || child.kind() == "triple_string"
            {
                let s = self.parse_string(child)?;
                return Ok(symbol_from_string(&s));
            }
        }
        if let Some(stripped) = text.strip_prefix("@?") {
            let name = format!("?{}", stripped);
            return Ok(Symbol {
                namespace: None,
                name,
            });
        }
        if let Some(stripped) = text.strip_prefix('\'') {
            let name = stripped.to_string();
            return Ok(Symbol {
                namespace: None,
                name,
            });
        }
        Err(FormatError::new(
            ErrorCode::Parse,
            "invalid symbol",
            Some(node.start_byte()),
        ))
    }

    fn parse_vector(&self, node: Node) -> Result<Value, FormatError> {
        let mut values = Vec::new();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "value" {
                values.push(self.parse_value(child)?);
            }
        }
        Ok(Value::Vector(values))
    }

    fn parse_set(&self, node: Node) -> Result<Value, FormatError> {
        let vector_node = node.named_child(0).ok_or_else(|| {
            FormatError::new(ErrorCode::Parse, "invalid set", Some(node.start_byte()))
        })?;
        let value = self.parse_vector(vector_node)?;
        if let Value::Vector(items) = value {
            Ok(Value::Set(items))
        } else {
            Err(FormatError::new(
                ErrorCode::Parse,
                "invalid set",
                Some(node.start_byte()),
            ))
        }
    }

    fn parse_map(&self, node: Node) -> Result<Value, FormatError> {
        let mut entries = Vec::new();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "map_entry" {
                entries.push(self.parse_map_entry(child)?);
            }
        }
        Ok(Value::Map(entries))
    }

    fn parse_map_entry(&self, node: Node) -> Result<(MapKey, Value), FormatError> {
        let mut cursor = node.walk();
        let mut iter = node.named_children(&mut cursor);
        let key_node = iter.next().ok_or_else(|| {
            FormatError::new(
                ErrorCode::Parse,
                "invalid map entry",
                Some(node.start_byte()),
            )
        })?;
        let value_node = iter.next().ok_or_else(|| {
            FormatError::new(
                ErrorCode::Parse,
                "invalid map entry",
                Some(node.start_byte()),
            )
        })?;
        let key = self.parse_map_key(key_node)?;
        let value = self.parse_value(value_node)?;
        Ok((key, value))
    }

    fn parse_map_key(&self, node: Node) -> Result<MapKey, FormatError> {
        let node = self.unwrap_value(node);
        match node.kind() {
            "identifier" | "lower_identifier" | "keyword_identifier" | "constructor" => {
                Ok(MapKey::Identifier(self.node_text(node)?.to_string()))
            }
            "keyword" => self.parse_keyword(node).map(MapKey::Keyword),
            "string" | "double_string" | "triple_string" => {
                let s = self.parse_string(node)?;
                Ok(MapKey::String(s))
            }
            "map_key" => {
                if let Some(child) = node.named_child(0) {
                    self.parse_map_key(child)
                } else {
                    Ok(MapKey::Identifier(self.node_text(node)?.to_string()))
                }
            }
            _ => Err(FormatError::new(
                ErrorCode::Parse,
                "invalid map key",
                Some(node.start_byte()),
            )),
        }
    }

    fn parse_tagged(&self, node: Node) -> Result<Value, FormatError> {
        let mut cursor = node.walk();
        let mut iter = node.named_children(&mut cursor);
        let first = iter.next().ok_or_else(|| {
            FormatError::new(ErrorCode::Parse, "invalid tagged", Some(node.start_byte()))
        })?;
        match first.kind() {
            "constructor" => {
                let name = self.node_text(first)?.to_string();
                let args = iter.next().map(|n| self.parse_args(n)).transpose()?;
                if name == "Set" {
                    return Ok(match args {
                        None => Value::Set(Vec::new()),
                        Some(Args::Positional(values)) => {
                            if values.len() == 1 {
                                if let Value::Vector(items) = values.into_iter().next().unwrap() {
                                    Value::Set(items)
                                } else {
                                    return Err(FormatError::new(
                                        ErrorCode::Parse,
                                        "Set() expects a vector argument",
                                        Some(node.start_byte()),
                                    ));
                                }
                            } else {
                                return Err(FormatError::new(
                                    ErrorCode::Parse,
                                    "Set() expects a vector argument",
                                    Some(node.start_byte()),
                                ));
                            }
                        }
                        Some(Args::Map(_)) => {
                            return Err(FormatError::new(
                                ErrorCode::Parse,
                                "Set() expects a vector argument",
                                Some(node.start_byte()),
                            ))
                        }
                    });
                }

                let value = args_to_value(args);
                let tag = symbol_from_pascal_case(&name);
                Ok(Value::Tagged(TaggedValue {
                    tag,
                    value: Box::new(value),
                }))
            }
            "string" | "double_string" | "triple_string" => {
                let tag_str = self.parse_string(first)?;
                let value_node = iter.next().ok_or_else(|| {
                    FormatError::new(ErrorCode::Parse, "invalid tagged", Some(node.start_byte()))
                })?;
                let value = self.parse_value(value_node)?;
                let tag = symbol_from_string(&tag_str);
                Ok(Value::Tagged(TaggedValue {
                    tag,
                    value: Box::new(value),
                }))
            }
            _ => Err(FormatError::new(
                ErrorCode::Parse,
                "invalid tagged",
                Some(node.start_byte()),
            )),
        }
    }

    fn parse_args(&self, node: Node) -> Result<Args, FormatError> {
        let node = self.unwrap_value(node);
        match node.kind() {
            "args" => {
                let child = node.named_child(0).ok_or_else(|| {
                    FormatError::new(ErrorCode::Parse, "invalid args", Some(node.start_byte()))
                })?;
                self.parse_args(child)
            }
            "map_args" => {
                let mut entries = Vec::new();
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if child.kind() == "map_entry" {
                        entries.push(self.parse_map_entry(child)?);
                    }
                }
                Ok(Args::Map(entries))
            }
            "value_args" => {
                let mut values = Vec::new();
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if child.kind() == "value" {
                        values.push(self.parse_value(child)?);
                    }
                }
                Ok(Args::Positional(values))
            }
            _ => Err(FormatError::new(
                ErrorCode::Parse,
                "invalid args",
                Some(node.start_byte()),
            )),
        }
    }

    fn parse_call(&self, node: Node) -> Result<Value, FormatError> {
        let mut cursor = node.walk();
        let mut iter = node.named_children(&mut cursor);
        let name_node = iter.next().ok_or_else(|| {
            FormatError::new(ErrorCode::Parse, "invalid call", Some(node.start_byte()))
        })?;
        let name = self.node_text(name_node)?.to_string();
        let args = iter.next().map(|n| self.parse_args(n)).transpose()?;
        let args = args.unwrap_or_else(|| Args::Positional(Vec::new()));
        Ok(Value::Call(Call { name, args }))
    }

    fn parse_import(&self, node: Node) -> Result<Value, FormatError> {
        let mut cursor = node.walk();
        let mut iter = node.named_children(&mut cursor);
        let path_node = iter.next().ok_or_else(|| {
            FormatError::new(ErrorCode::Parse, "invalid import", Some(node.start_byte()))
        })?;
        let path = self.parse_string(path_node)?;
        let hash = iter.next().map(|n| self.parse_hash_spec(n)).transpose()?;
        Ok(Value::Import(Import { path, hash }))
    }

    fn parse_hash_spec(&self, node: Node) -> Result<HashSpec, FormatError> {
        let text = self.node_text(node)?;
        let mut parts = text.splitn(2, ':');
        let alg = parts.next().unwrap_or("");
        let hex = parts.next().unwrap_or("");
        let algorithm = match alg {
            "sha256" => HashAlgorithm::Sha256,
            "blake3" => HashAlgorithm::Blake3,
            _ => {
                return Err(FormatError::new(
                    ErrorCode::InvalidImportHash,
                    "invalid import hash",
                    Some(node.start_byte()),
                ))
            }
        };
        if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(FormatError::new(
                ErrorCode::InvalidImportHash,
                "invalid import hash",
                Some(node.start_byte()),
            ));
        }
        Ok(HashSpec {
            algorithm,
            hex: hex.to_ascii_lowercase(),
        })
    }

    fn parse_generator(&self, node: Node) -> Result<Value, FormatError> {
        let text = self.node_text(node)?;
        let mut cursor = node.walk();
        let mut iter = node.named_children(&mut cursor);
        let keyword_node = iter.next().ok_or_else(|| {
            FormatError::new(
                ErrorCode::Parse,
                "invalid generator",
                Some(node.start_byte()),
            )
        })?;
        let keyword = self.parse_keyword(keyword_node)?;
        let kind = if text.starts_with("@new") {
            GeneratorKind::New
        } else {
            GeneratorKind::Generator
        };
        Ok(Value::Generator(Generator { kind, keyword }))
    }

    fn parse_let(&self, node: Node) -> Result<Value, FormatError> {
        let mut cursor = node.walk();
        let mut iter = node.named_children(&mut cursor);
        let first = iter.next().ok_or_else(|| {
            FormatError::new(ErrorCode::Parse, "invalid let", Some(node.start_byte()))
        })?;
        let body_node = iter.next().ok_or_else(|| {
            FormatError::new(ErrorCode::Parse, "invalid let", Some(node.start_byte()))
        })?;
        let bindings = match first.kind() {
            "binding" => vec![self.parse_binding(first)?],
            "block" => self.parse_block(first)?,
            _ => {
                return Err(FormatError::new(
                    ErrorCode::Parse,
                    "invalid let",
                    Some(node.start_byte()),
                ))
            }
        };
        let body = self.parse_value(body_node)?;
        Ok(Value::Let(LetExpr {
            bindings,
            body: Box::new(body),
        }))
    }

    fn parse_binding(&self, node: Node) -> Result<Binding, FormatError> {
        let mut cursor = node.walk();
        let mut iter = node.named_children(&mut cursor);
        let target = iter.next().ok_or_else(|| {
            FormatError::new(ErrorCode::Parse, "invalid binding", Some(node.start_byte()))
        })?;
        let value_node = iter.next().ok_or_else(|| {
            FormatError::new(ErrorCode::Parse, "invalid binding", Some(node.start_byte()))
        })?;
        let pattern = match target.kind() {
            "identifier" => Pattern::Identifier(self.node_text(target)?.to_string()),
            "pattern" => self.parse_pattern(target)?,
            _ => {
                return Err(FormatError::new(
                    ErrorCode::Parse,
                    "invalid binding",
                    Some(node.start_byte()),
                ))
            }
        };
        let value = self.parse_value(value_node)?;
        Ok(Binding { pattern, value })
    }

    fn parse_block(&self, node: Node) -> Result<Vec<Binding>, FormatError> {
        let mut bindings = Vec::new();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "binding" {
                bindings.push(self.parse_binding(child)?);
            }
        }
        Ok(bindings)
    }

    fn parse_pattern(&self, node: Node) -> Result<Pattern, FormatError> {
        let mut names = Vec::new();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "identifier" {
                names.push(self.node_text(child)?.to_string());
            }
        }
        let text = self.node_text(node)?;
        if text.starts_with('(') {
            Ok(Pattern::Tuple(names))
        } else {
            Ok(Pattern::Vector(names))
        }
    }

    fn parse_fn(&self, node: Node) -> Result<Value, FormatError> {
        let mut cursor = node.walk();
        let mut iter = node.named_children(&mut cursor);
        let first = iter.next();
        let (params_node, body_node) = match first {
            Some(node) if node.kind() == "params" => {
                let body = iter.next().ok_or_else(|| {
                    FormatError::new(ErrorCode::Parse, "invalid fn", Some(node.start_byte()))
                })?;
                (Some(node), body)
            }
            Some(node) => (None, node),
            None => {
                return Err(FormatError::new(
                    ErrorCode::Parse,
                    "invalid fn",
                    Some(node.start_byte()),
                ))
            }
        };
        let params = if let Some(params_node) = params_node {
            self.parse_params(params_node)?
        } else {
            Vec::new()
        };
        let body = self.parse_value(body_node)?;
        Ok(Value::Fn(FnExpr {
            params,
            body: Box::new(body),
        }))
    }

    fn parse_params(&self, node: Node) -> Result<Vec<String>, FormatError> {
        let mut params = Vec::new();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "identifier" {
                params.push(self.node_text(child)?.to_string());
            }
        }
        Ok(params)
    }

    fn parse_ns(&self, node: Node) -> Result<Value, FormatError> {
        let mut cursor = node.walk();
        let mut iter = node.named_children(&mut cursor);
        let ns_node = iter.next().ok_or_else(|| {
            FormatError::new(ErrorCode::Parse, "invalid @ns", Some(node.start_byte()))
        })?;
        let value_node = iter.next().ok_or_else(|| {
            FormatError::new(ErrorCode::Parse, "invalid @ns", Some(node.start_byte()))
        })?;
        let namespace = self.node_text(ns_node)?.to_string();
        let value = self.parse_value(value_node)?;
        Ok(Value::Ns(NsMacro {
            namespace,
            value: Box::new(value),
        }))
    }

    fn parse_infix(&self, node: Node) -> Result<Value, FormatError> {
        let mut items = Vec::new();
        let mut operators = Vec::new();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "value" => items.push(self.parse_value(child)?),
                "infix_operator" => operators.push(self.node_text(child)?.to_string()),
                _ => {}
            }
        }
        if items.len() != operators.len() + 1 {
            return Err(FormatError::new(
                ErrorCode::Parse,
                "invalid infix expression",
                Some(node.start_byte()),
            ));
        }
        Ok(Value::Infix(InfixExpr { items, operators }))
    }

    fn parse_annotated(&self, node: Node) -> Result<Value, FormatError> {
        let (metadata, value) = self.parse_annotation_layers(node)?;
        Ok(Value::Annotated(Annotation {
            metadata,
            value: Box::new(value),
        }))
    }

    fn parse_annotation_layers(
        &self,
        node: Node,
    ) -> Result<(Vec<(MapKey, Value)>, Value), FormatError> {
        let node = self.unwrap_value(node);
        if node.kind() != "annotated" {
            let value = self.parse_value(node)?;
            return Ok((Vec::new(), value));
        }

        let mut cursor = node.walk();
        let mut iter = node.named_children(&mut cursor);
        let first = iter.next().ok_or_else(|| {
            FormatError::new(
                ErrorCode::Parse,
                "invalid annotation",
                Some(node.start_byte()),
            )
        })?;
        let second = iter.next().ok_or_else(|| {
            FormatError::new(
                ErrorCode::Parse,
                "invalid annotation",
                Some(node.start_byte()),
            )
        })?;

        let mut metadata = Vec::new();
        match first.kind() {
            "meta" => metadata.extend(self.parse_meta(first)?),
            "docstring" => {
                let doc = self.parse_docstring(first)?;
                metadata.push((MapKey::Keyword(keyword_doc()), Value::String(doc)));
            }
            _ => {
                return Err(FormatError::new(
                    ErrorCode::Parse,
                    "invalid annotation",
                    Some(node.start_byte()),
                ))
            }
        }

        let (mut inner_metadata, value) = self.parse_annotation_layers(second)?;
        metadata.append(&mut inner_metadata);
        Ok((metadata, value))
    }

    fn parse_meta(&self, node: Node) -> Result<Vec<(MapKey, Value)>, FormatError> {
        let mut entries = Vec::new();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "map_args" {
                let mut args_cursor = child.walk();
                for entry in child.named_children(&mut args_cursor) {
                    if entry.kind() == "map_entry" {
                        entries.push(self.parse_map_entry(entry)?);
                    }
                }
            }
        }
        Ok(entries)
    }

    fn parse_docstring(&self, node: Node) -> Result<String, FormatError> {
        let child = node.named_child(0).ok_or_else(|| {
            FormatError::new(
                ErrorCode::InvalidString,
                "invalid docstring",
                Some(node.start_byte()),
            )
        })?;
        self.parse_string(child)
    }

    fn node_text(&self, node: Node) -> Result<&'a str, FormatError> {
        node.utf8_text(self.source.as_bytes()).map_err(|_| {
            FormatError::new(ErrorCode::Parse, "invalid utf-8", Some(node.start_byte()))
        })
    }
}

fn args_to_value(args: Option<Args>) -> Value {
    match args {
        None => Value::Map(Vec::new()),
        Some(Args::Map(entries)) => Value::Map(entries),
        Some(Args::Positional(values)) => {
            if values.len() == 1 {
                values.into_iter().next().unwrap()
            } else {
                Value::Vector(values)
            }
        }
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

fn keyword_from_string(text: &str) -> Keyword {
    if let Some((ns, name)) = text.split_once('/') {
        Keyword {
            namespace: Some(ns.to_string()),
            name: name.to_string(),
        }
    } else {
        Keyword {
            namespace: None,
            name: text.to_string(),
        }
    }
}

fn keyword_doc() -> Keyword {
    Keyword {
        namespace: None,
        name: "doc".to_string(),
    }
}

fn symbol_from_string(text: &str) -> Symbol {
    if let Some((ns, name)) = text.split_once('/') {
        Symbol {
            namespace: Some(ns.to_string()),
            name: name.to_string(),
        }
    } else {
        Symbol {
            namespace: None,
            name: text.to_string(),
        }
    }
}

fn symbol_from_pascal_case(name: &str) -> Symbol {
    if name
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return Symbol {
            namespace: None,
            name: name.to_ascii_lowercase(),
        };
    }

    let mut parts = Vec::new();
    let mut current = String::new();
    let mut prev_lower = false;

    for ch in name.chars() {
        let is_upper = ch.is_ascii_uppercase();
        if is_upper && prev_lower && !current.is_empty() {
            parts.push(current.to_ascii_lowercase());
            current = String::new();
        }
        current.push(ch);
        prev_lower = ch.is_ascii_lowercase();
    }
    if !current.is_empty() {
        parts.push(current.to_ascii_lowercase());
    }

    if parts.len() >= 2 {
        let ns = parts[0].clone();
        let name = parts[1..].join("-");
        Symbol {
            namespace: Some(ns),
            name,
        }
    } else if parts.len() == 1 {
        Symbol {
            namespace: None,
            name: parts[0].clone(),
        }
    } else {
        Symbol {
            namespace: None,
            name: name.to_ascii_lowercase(),
        }
    }
}
