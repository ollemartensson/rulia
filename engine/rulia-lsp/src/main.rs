use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tower_lsp::lsp_types::{
    Diagnostic, DiagnosticSeverity, DidChangeTextDocumentParams, DidCloseTextDocumentParams,
    DidOpenTextDocumentParams, DocumentFormattingParams, InitializeParams, InitializeResult,
    NumberOrString, OneOf, Position, Range, ServerCapabilities, TextDocumentSyncCapability,
    TextDocumentSyncKind, TextEdit, Url,
};
use tower_lsp::{Client, LanguageServer, LspService, Server};
use tree_sitter::{Parser, Tree};

#[derive(Clone)]
struct DocumentSnapshot {
    version: i32,
    text: String,
    tree: Option<Tree>,
}

#[derive(Default)]
struct DocumentStore {
    documents: HashMap<Url, DocumentSnapshot>,
}

struct Backend {
    client: Client,
    store: Arc<Mutex<DocumentStore>>,
}

impl Backend {
    fn new(client: Client) -> Self {
        Self {
            client,
            store: Arc::new(Mutex::new(DocumentStore::default())),
        }
    }

    fn schedule_diagnostics(&self, uri: Url, version: i32) {
        let store = Arc::clone(&self.store);
        let client = self.client.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let (text, previous_tree) = {
                let store = store.lock().await;
                let Some(snapshot) = store.documents.get(&uri) else {
                    return;
                };
                if snapshot.version != version {
                    return;
                }
                (snapshot.text.clone(), snapshot.tree.clone())
            };
            let tree = parse_tree(&text, previous_tree.as_ref());
            let diagnostics = compute_diagnostics_from_tree(&text, &tree);
            {
                let mut store = store.lock().await;
                let Some(snapshot) = store.documents.get_mut(&uri) else {
                    return;
                };
                if snapshot.version != version {
                    return;
                }
                snapshot.tree = Some(tree.clone());
            }
            client
                .publish_diagnostics(uri, diagnostics, Some(version))
                .await;
        });
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(
        &self,
        _: InitializeParams,
    ) -> tower_lsp::jsonrpc::Result<InitializeResult> {
        let capabilities = ServerCapabilities {
            text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
            document_formatting_provider: Some(OneOf::Left(true)),
            ..ServerCapabilities::default()
        };
        Ok(InitializeResult {
            capabilities,
            ..InitializeResult::default()
        })
    }

    async fn shutdown(&self) -> tower_lsp::jsonrpc::Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let doc = params.text_document;
        let uri = doc.uri;
        let version = doc.version;
        let text = doc.text;
        {
            let mut store = self.store.lock().await;
            store.documents.insert(
                uri.clone(),
                DocumentSnapshot {
                    version,
                    text,
                    tree: None,
                },
            );
        }
        self.schedule_diagnostics(uri, version);
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri;
        let version = params.text_document.version;
        let text = params
            .content_changes
            .last()
            .map(|change| change.text.clone())
            .unwrap_or_default();
        {
            let mut store = self.store.lock().await;
            let previous_tree = store
                .documents
                .get(&uri)
                .and_then(|snapshot| snapshot.tree.clone());
            store.documents.insert(
                uri.clone(),
                DocumentSnapshot {
                    version,
                    text,
                    tree: previous_tree,
                },
            );
        }
        self.schedule_diagnostics(uri, version);
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri;
        {
            let mut store = self.store.lock().await;
            store.documents.remove(&uri);
        }
        self.client.publish_diagnostics(uri, Vec::new(), None).await;
    }

    async fn formatting(
        &self,
        params: DocumentFormattingParams,
    ) -> tower_lsp::jsonrpc::Result<Option<Vec<TextEdit>>> {
        let uri = params.text_document.uri;
        let text = {
            let store = self.store.lock().await;
            store.documents.get(&uri).map(|doc| doc.text.clone())
        };
        let Some(text) = text else {
            return Ok(None);
        };
        let Some(canonical) = compute_format(&text) else {
            return Ok(None);
        };
        if canonical == text {
            return Ok(Some(Vec::new()));
        }
        let end = utf16_end_position(&text);
        let edit = TextEdit {
            range: Range::new(Position::new(0, 0), end),
            new_text: canonical,
        };
        Ok(Some(vec![edit]))
    }
}

#[cfg(test)]
fn compute_diagnostics(text: &str) -> Vec<Diagnostic> {
    let tree = parse_tree(text, None);
    compute_diagnostics_from_tree(text, &tree)
}

fn compute_format(text: &str) -> Option<String> {
    rulia_fmt::format(text).ok()
}

fn utf16_end_position(text: &str) -> Position {
    let (line, col) = byte_offset_to_utf16_position(text, text.len());
    Position::new(line, col)
}

fn parse_tree(text: &str, previous: Option<&Tree>) -> Tree {
    let mut parser = Parser::new();
    let language = tree_sitter_rulia::language();
    parser
        .set_language(&language)
        .expect("tree-sitter-rulia language load failed");
    parser
        .parse(text, previous)
        .expect("tree-sitter parse failed")
}

fn compute_diagnostics_from_tree(text: &str, tree: &Tree) -> Vec<Diagnostic> {
    let syntax = compute_syntax_diagnostics_from_tree(text, tree);
    if !syntax.is_empty() {
        return syntax;
    }
    compute_semantic_diagnostics_from_tree(text, tree)
}

fn compute_syntax_diagnostics_from_tree(text: &str, tree: &Tree) -> Vec<Diagnostic> {
    let root = tree.root_node();
    if !root.has_error() {
        return Vec::new();
    }
    let mut error_nodes = Vec::new();
    collect_leaf_error_nodes(root, &mut error_nodes);
    let mut diagnostics = Vec::new();
    let mut seen = HashSet::new();
    for node in error_nodes {
        let message = if node.is_missing() {
            "missing token"
        } else {
            "syntax error"
        };
        let range = byte_range_to_lsp_range(text, node.start_byte(), node.end_byte());
        let key = DiagnosticKey::new(&range, message);
        if seen.insert(key) {
            diagnostics.push(Diagnostic {
                range,
                severity: Some(DiagnosticSeverity::ERROR),
                code: None,
                code_description: None,
                source: Some("tree-sitter".to_string()),
                message: message.to_string(),
                related_information: None,
                tags: None,
                data: None,
            });
        }
    }
    diagnostics
}

fn compute_semantic_diagnostics_from_tree(text: &str, tree: &Tree) -> Vec<Diagnostic> {
    const MAX_SEMANTIC_NODES: usize = 50_000;
    let mut diagnostics = Vec::new();
    let mut stack = vec![tree.root_node()];
    let mut visited = 0usize;
    let mut truncated = false;
    while let Some(node) = stack.pop() {
        visited += 1;
        if visited > MAX_SEMANTIC_NODES {
            truncated = true;
            break;
        }
        if node.is_error() || node.is_missing() {
            continue;
        }
        match node.kind() {
            "tagged" => check_tagged_node(text, node, &mut diagnostics),
            "map" => check_envelope_map(text, node, &mut diagnostics),
            _ => {}
        }
        let mut cursor = node.walk();
        let mut children = Vec::new();
        for child in node.children(&mut cursor) {
            children.push(child);
        }
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }
    if truncated {
        diagnostics.push(Diagnostic {
            range: Range::new(Position::new(0, 0), Position::new(0, 0)),
            severity: Some(DiagnosticSeverity::WARNING),
            code: Some(NumberOrString::String("SEMANTIC_LIMIT_REACHED".to_string())),
            code_description: None,
            source: Some("rulia-lsp".to_string()),
            message: "semantic diagnostics truncated after node limit".to_string(),
            related_information: None,
            tags: None,
            data: None,
        });
    }
    diagnostics.sort_by(|left, right| {
        let left_start = (left.range.start.line, left.range.start.character);
        let right_start = (right.range.start.line, right.range.start.character);
        left_start.cmp(&right_start).then_with(|| {
            let left_code = diagnostic_code_string(left);
            let right_code = diagnostic_code_string(right);
            left_code.cmp(right_code)
        })
    });
    diagnostics
}

fn diagnostic_code_string(diagnostic: &Diagnostic) -> &str {
    match diagnostic.code.as_ref() {
        Some(NumberOrString::String(code)) => code.as_str(),
        _ => "",
    }
}

fn check_tagged_node(text: &str, node: tree_sitter::Node<'_>, diagnostics: &mut Vec<Diagnostic>) {
    if let Some(constructor_node) = direct_child_by_kind(node, "constructor") {
        let name = node_text(text, constructor_node);
        match name {
            "Tagged" => check_explicit_tagged_constructor(text, node, diagnostics),
            "Decimal" => check_decimal_constructor(text, node, diagnostics),
            "Path" => check_path_constructor(text, node, diagnostics),
            "Expr" => check_expr_constructor(text, node, diagnostics),
            "Instant" => check_instant_constructor(text, node, diagnostics),
            _ => {}
        }
        return;
    }
    let tag_node = direct_child_by_kind(node, "string");
    let payload_node = direct_child_by_kind(node, "value");
    let (Some(tag_node), Some(payload_node)) = (tag_node, payload_node) else {
        return;
    };
    let Some(tag) = parse_string_literal(text, tag_node) else {
        return;
    };
    match tag.as_str() {
        "decimal" => check_decimal_payload(text, payload_node, diagnostics),
        "path" => check_path_payload(text, payload_node, diagnostics),
        "expr" => check_expr_payload(text, payload_node, diagnostics),
        _ => {}
    }
}

fn check_explicit_tagged_constructor(
    text: &str,
    node: tree_sitter::Node<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let args = constructor_value_args(node);
    let Some(values) = args else {
        return;
    };
    if values.len() != 2 {
        return;
    }
    let tag_node = unwrap_value_node(values[0]);
    if tag_node.kind() != "string" {
        return;
    }
    let Some(tag) = parse_string_literal(text, tag_node) else {
        return;
    };
    let payload_node = values[1];
    match tag.as_str() {
        "decimal" => check_decimal_payload(text, payload_node, diagnostics),
        "path" => check_path_payload(text, payload_node, diagnostics),
        "expr" => check_expr_payload(text, payload_node, diagnostics),
        _ => {}
    }
}

fn check_decimal_constructor(
    text: &str,
    node: tree_sitter::Node<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let range = byte_range_to_lsp_range(text, node.start_byte(), node.end_byte());
    let args = constructor_value_args(node);
    let arg = args.as_ref().and_then(|values| {
        if values.len() == 1 {
            Some(values[0])
        } else {
            None
        }
    });
    let Some(arg) = arg else {
        push_semantic_diagnostic(
            diagnostics,
            range,
            DiagnosticSeverity::ERROR,
            "DECIMAL_INVALID",
            "decimal constructor expects a single string literal",
        );
        return;
    };
    check_decimal_string_node(text, arg, diagnostics);
}

fn check_decimal_payload(
    text: &str,
    payload: tree_sitter::Node<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    check_decimal_string_node(text, payload, diagnostics);
}

fn check_decimal_string_node(
    text: &str,
    node: tree_sitter::Node<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let value_node = unwrap_value_node(node);
    let range = byte_range_to_lsp_range(text, value_node.start_byte(), value_node.end_byte());
    if value_node.kind() != "string" {
        push_semantic_diagnostic(
            diagnostics,
            range,
            DiagnosticSeverity::ERROR,
            "DECIMAL_INVALID",
            "decimal payload must be a string literal",
        );
        return;
    }
    let Some(value) = parse_string_literal(text, value_node) else {
        push_semantic_diagnostic(
            diagnostics,
            range,
            DiagnosticSeverity::ERROR,
            "DECIMAL_INVALID",
            "decimal payload must be a string literal",
        );
        return;
    };
    match canonical_decimal_string(&value) {
        Ok(canonical) => {
            if canonical != value {
                push_semantic_diagnostic(
                    diagnostics,
                    range,
                    DiagnosticSeverity::ERROR,
                    "DECIMAL_NONCANONICAL",
                    "decimal string is not in canonical form",
                );
            }
        }
        Err(_) => {
            push_semantic_diagnostic(
                diagnostics,
                range,
                DiagnosticSeverity::ERROR,
                "DECIMAL_INVALID",
                "decimal string is invalid",
            );
        }
    }
}

fn check_path_constructor(
    text: &str,
    node: tree_sitter::Node<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let args = constructor_value_args(node);
    let arg = args.as_ref().and_then(|values| {
        if values.len() == 1 {
            Some(values[0])
        } else {
            None
        }
    });
    let Some(arg) = arg else {
        let range = byte_range_to_lsp_range(text, node.start_byte(), node.end_byte());
        push_semantic_diagnostic(
            diagnostics,
            range,
            DiagnosticSeverity::ERROR,
            "PATH_INVALID_SHAPE",
            "path constructor expects a single vector literal",
        );
        return;
    };
    check_path_payload(text, arg, diagnostics);
}

fn check_path_payload(
    text: &str,
    payload: tree_sitter::Node<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let payload_node = unwrap_value_node(payload);
    if payload_node.kind() != "vector" {
        let range =
            byte_range_to_lsp_range(text, payload_node.start_byte(), payload_node.end_byte());
        push_semantic_diagnostic(
            diagnostics,
            range,
            DiagnosticSeverity::ERROR,
            "PATH_INVALID_SHAPE",
            "path payload must be a vector literal",
        );
        return;
    }
    let segments = vector_values(payload_node);
    if segments.is_empty() {
        let range =
            byte_range_to_lsp_range(text, payload_node.start_byte(), payload_node.end_byte());
        push_semantic_diagnostic(
            diagnostics,
            range,
            DiagnosticSeverity::ERROR,
            "PATH_INVALID_SHAPE",
            "path must contain at least one segment",
        );
        return;
    }
    for segment in segments {
        validate_path_segment(text, segment, diagnostics);
    }
}

fn validate_path_segment(
    text: &str,
    segment: tree_sitter::Node<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let value_node = unwrap_value_node(segment);
    let range = byte_range_to_lsp_range(text, value_node.start_byte(), value_node.end_byte());
    match value_node.kind() {
        "string" => {
            let Some(value) = parse_string_literal(text, value_node) else {
                push_semantic_diagnostic(
                    diagnostics,
                    range,
                    DiagnosticSeverity::ERROR,
                    "PATH_INVALID_SEGMENT",
                    "path segment must be a string literal",
                );
                return;
            };
            if value.is_empty() {
                push_semantic_diagnostic(
                    diagnostics,
                    range,
                    DiagnosticSeverity::ERROR,
                    "PATH_INVALID_SEGMENT",
                    "path string segments must be non-empty",
                );
            }
        }
        "keyword" | "tagged" => {
            let Some(keyword) = parse_keyword_like(text, value_node) else {
                push_semantic_diagnostic(
                    diagnostics,
                    range,
                    DiagnosticSeverity::ERROR,
                    "PATH_INVALID_SEGMENT",
                    "path keyword segments must be canonical",
                );
                return;
            };
            if !keyword.has_namespace {
                push_semantic_diagnostic(
                    diagnostics,
                    range,
                    DiagnosticSeverity::ERROR,
                    "PATH_INVALID_SEGMENT",
                    "path keyword segments must be namespaced",
                );
            }
        }
        "number" => {
            let Some(kind) = number_kind(value_node) else {
                push_semantic_diagnostic(
                    diagnostics,
                    range,
                    DiagnosticSeverity::ERROR,
                    "PATH_INVALID_SEGMENT",
                    "path numeric segments must be integers",
                );
                return;
            };
            match kind {
                "int" => {
                    let Some(value) = parse_int_literal(text, value_node) else {
                        push_semantic_diagnostic(
                            diagnostics,
                            range,
                            DiagnosticSeverity::ERROR,
                            "PATH_INVALID_SEGMENT",
                            "path integer segments must be valid",
                        );
                        return;
                    };
                    if value < 0 {
                        push_semantic_diagnostic(
                            diagnostics,
                            range,
                            DiagnosticSeverity::ERROR,
                            "PATH_INVALID_SEGMENT",
                            "path integer segments must be non-negative",
                        );
                    } else if value as u128 > MAX_JS_SAFE_INTEGER {
                        push_semantic_diagnostic(
                            diagnostics,
                            range,
                            DiagnosticSeverity::WARNING,
                            "PATH_INT_UNSAFE",
                            "path integer exceeds JS safe integer range",
                        );
                    }
                }
                "uint" => {
                    let Some(value) = parse_uint_literal(text, value_node) else {
                        push_semantic_diagnostic(
                            diagnostics,
                            range,
                            DiagnosticSeverity::ERROR,
                            "PATH_INVALID_SEGMENT",
                            "path integer segments must be valid",
                        );
                        return;
                    };
                    if value > MAX_JS_SAFE_INTEGER {
                        push_semantic_diagnostic(
                            diagnostics,
                            range,
                            DiagnosticSeverity::WARNING,
                            "PATH_INT_UNSAFE",
                            "path integer exceeds JS safe integer range",
                        );
                    }
                }
                _ => {
                    push_semantic_diagnostic(
                        diagnostics,
                        range,
                        DiagnosticSeverity::ERROR,
                        "PATH_INVALID_SEGMENT",
                        "path segments must be integers, strings, or keywords",
                    );
                }
            }
        }
        _ => {
            push_semantic_diagnostic(
                diagnostics,
                range,
                DiagnosticSeverity::ERROR,
                "PATH_INVALID_SEGMENT",
                "path segments must be integers, strings, or keywords",
            );
        }
    }
}

fn check_expr_constructor(
    text: &str,
    node: tree_sitter::Node<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let args = constructor_value_args(node);
    let arg = args.as_ref().and_then(|values| {
        if values.len() == 1 {
            Some(values[0])
        } else {
            None
        }
    });
    let Some(arg) = arg else {
        let range = byte_range_to_lsp_range(text, node.start_byte(), node.end_byte());
        push_semantic_diagnostic(
            diagnostics,
            range,
            DiagnosticSeverity::ERROR,
            "EXPR_INVALID_OP",
            "expr constructor expects a single vector literal",
        );
        return;
    };
    check_expr_payload(text, arg, diagnostics);
}

fn check_expr_payload(
    text: &str,
    payload: tree_sitter::Node<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let payload_node = unwrap_value_node(payload);
    if payload_node.kind() != "vector" {
        let range =
            byte_range_to_lsp_range(text, payload_node.start_byte(), payload_node.end_byte());
        push_semantic_diagnostic(
            diagnostics,
            range,
            DiagnosticSeverity::ERROR,
            "EXPR_INVALID_OP",
            "expr payload must be a vector literal",
        );
        return;
    }
    let elements = vector_values(payload_node);
    if elements.is_empty() {
        let range =
            byte_range_to_lsp_range(text, payload_node.start_byte(), payload_node.end_byte());
        push_semantic_diagnostic(
            diagnostics,
            range,
            DiagnosticSeverity::ERROR,
            "EXPR_INVALID_OP",
            "expr vector must include an operator",
        );
        return;
    }
    let op_node = unwrap_value_node(elements[0]);
    let op_range = byte_range_to_lsp_range(text, op_node.start_byte(), op_node.end_byte());
    let Some(op_keyword) = parse_keyword_like(text, op_node) else {
        push_semantic_diagnostic(
            diagnostics,
            op_range,
            DiagnosticSeverity::ERROR,
            "EXPR_INVALID_OP",
            "expr operator must be a keyword",
        );
        return;
    };
    if op_keyword.has_namespace {
        push_semantic_diagnostic(
            diagnostics,
            op_range,
            DiagnosticSeverity::ERROR,
            "EXPR_INVALID_OP",
            "expr operator must be non-namespaced",
        );
        return;
    }
    let op = op_keyword.canonical.as_str();
    let rule = match op {
        "not" => ArityRule::Exact(1),
        "and" | "or" => ArityRule::Min(2),
        "==" | "!=" | "<" | "<=" | ">" | ">=" | "in" => ArityRule::Exact(2),
        _ => {
            push_semantic_diagnostic(
                diagnostics,
                op_range,
                DiagnosticSeverity::ERROR,
                "EXPR_INVALID_OP",
                "expr operator is not part of Expr v0",
            );
            return;
        }
    };
    let args = &elements[1..];
    let arity_ok = match rule {
        ArityRule::Exact(n) => args.len() == n,
        ArityRule::Min(n) => args.len() >= n,
    };
    if !arity_ok {
        push_semantic_diagnostic(
            diagnostics,
            op_range,
            DiagnosticSeverity::ERROR,
            "EXPR_INVALID_ARITY",
            "expr operator has the wrong arity",
        );
        return;
    }
    let is_comparison = matches!(op, "==" | "!=" | "<" | "<=" | ">" | ">=" | "in");
    let mut nil_positions = Vec::new();
    for (idx, arg) in args.iter().enumerate() {
        let arg_node = unwrap_value_node(*arg);
        let arg_range = byte_range_to_lsp_range(text, arg_node.start_byte(), arg_node.end_byte());
        if is_comparison && arg_node.kind() == "bytes" {
            push_semantic_diagnostic(
                diagnostics,
                arg_range,
                DiagnosticSeverity::ERROR,
                "EXPR_FORBIDDEN_TYPE",
                "expr comparisons may not use bytes",
            );
        }
        if arg_node.kind() == "nil" {
            nil_positions.push((idx, arg_range));
        }
    }
    if !nil_positions.is_empty() {
        if op != "==" && op != "!=" {
            for (_, range) in nil_positions {
                push_semantic_diagnostic(
                    diagnostics,
                    range,
                    DiagnosticSeverity::ERROR,
                    "EXPR_FORBIDDEN_TYPE",
                    "nil comparisons are only allowed with == or !=",
                );
            }
        } else if args.len() == 2 {
            let other_is_nil = args
                .iter()
                .all(|arg| unwrap_value_node(*arg).kind() == "nil");
            if !other_is_nil {
                for (_, range) in nil_positions {
                    push_semantic_diagnostic(
                        diagnostics,
                        range,
                        DiagnosticSeverity::ERROR,
                        "EXPR_FORBIDDEN_TYPE",
                        "nil comparisons must compare nil with nil",
                    );
                }
            }
        }
    }
}

fn check_instant_constructor(
    text: &str,
    node: tree_sitter::Node<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let range = byte_range_to_lsp_range(text, node.start_byte(), node.end_byte());
    let args = constructor_value_args(node);
    let arg = args.as_ref().and_then(|values| {
        if values.len() == 1 {
            Some(values[0])
        } else {
            None
        }
    });
    let Some(arg) = arg else {
        push_semantic_diagnostic(
            diagnostics,
            range,
            DiagnosticSeverity::ERROR,
            "INSTANT_INVALID",
            "Instant constructor expects a single string literal",
        );
        return;
    };
    let value_node = unwrap_value_node(arg);
    let value_range = byte_range_to_lsp_range(text, value_node.start_byte(), value_node.end_byte());
    if value_node.kind() != "string" {
        push_semantic_diagnostic(
            diagnostics,
            value_range,
            DiagnosticSeverity::ERROR,
            "INSTANT_INVALID",
            "Instant payload must be a string literal",
        );
        return;
    }
    let Some(value) = parse_string_literal(text, value_node) else {
        push_semantic_diagnostic(
            diagnostics,
            value_range,
            DiagnosticSeverity::ERROR,
            "INSTANT_INVALID",
            "Instant payload must be a string literal",
        );
        return;
    };
    match validate_instant_string(&value) {
        InstantValidity::Canonical => {}
        InstantValidity::NonCanonical => {
            push_semantic_diagnostic(
                diagnostics,
                value_range,
                DiagnosticSeverity::ERROR,
                "INSTANT_NONCANONICAL",
                "Instant string is not in canonical form",
            );
        }
        InstantValidity::Invalid => {
            push_semantic_diagnostic(
                diagnostics,
                value_range,
                DiagnosticSeverity::ERROR,
                "INSTANT_INVALID",
                "Instant string is invalid",
            );
        }
    }
}

fn check_envelope_map(text: &str, node: tree_sitter::Node<'_>, diagnostics: &mut Vec<Diagnostic>) {
    let mut kind_key: Option<MapKeyInfo> = None;
    let mut payload_key: Option<MapKeyInfo> = None;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "map_entry" {
            continue;
        }
        let Some(info) = map_entry_key_info(text, child) else {
            continue;
        };
        match info.name.as_str() {
            "kind" => kind_key = Some(info),
            "payload" => payload_key = Some(info),
            _ => {}
        }
    }
    let (Some(kind_key), Some(payload_key)) = (kind_key, payload_key) else {
        return;
    };
    for info in [kind_key, payload_key] {
        if info.kind != MapKeyKind::String {
            push_semantic_diagnostic(
                diagnostics,
                info.range,
                DiagnosticSeverity::WARNING,
                "ENVELOPE_KEY_SHOULD_BE_STRING",
                "envelope keys should use string literals for JS-friendly shape",
            );
        }
    }
}

fn constructor_value_args<'a>(node: tree_sitter::Node<'a>) -> Option<Vec<tree_sitter::Node<'a>>> {
    let args_node = direct_child_by_kind(node, "args")?;
    let mut cursor = args_node.walk();
    for child in args_node.children(&mut cursor) {
        match child.kind() {
            "value_args" => {
                let mut values = Vec::new();
                let mut child_cursor = child.walk();
                for value in child.children(&mut child_cursor) {
                    if value.kind() == "value" {
                        values.push(value);
                    }
                }
                return Some(values);
            }
            "map_args" => return None,
            _ => {}
        }
    }
    None
}

fn vector_values<'a>(node: tree_sitter::Node<'a>) -> Vec<tree_sitter::Node<'a>> {
    let mut values = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "value" {
            values.push(child);
        }
    }
    values
}

fn unwrap_value_node<'a>(node: tree_sitter::Node<'a>) -> tree_sitter::Node<'a> {
    if node.kind() == "value" {
        node.named_child(0).unwrap_or(node)
    } else {
        node
    }
}

fn direct_child_by_kind<'a>(
    node: tree_sitter::Node<'a>,
    kind: &str,
) -> Option<tree_sitter::Node<'a>> {
    let mut cursor = node.walk();
    let result = node
        .children(&mut cursor)
        .find(|child| child.kind() == kind);
    result
}

fn node_text<'a>(text: &'a str, node: tree_sitter::Node<'_>) -> &'a str {
    let start = node.start_byte().min(text.len());
    let end = node.end_byte().min(text.len());
    &text[start..end]
}

fn parse_string_literal(text: &str, node: tree_sitter::Node<'_>) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    if node_has_descendant_kind(node, "interpolation") {
        return None;
    }
    let raw = node_text(text, node);
    if raw.starts_with("\"\"\"") {
        decode_triple_string(raw)
    } else if raw.starts_with('\"') {
        decode_double_string(raw)
    } else {
        None
    }
}

fn node_has_descendant_kind<'a>(node: tree_sitter::Node<'a>, kind: &str) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == kind {
            return true;
        }
        let mut cursor = current.walk();
        for child in current.children(&mut cursor) {
            stack.push(child);
        }
    }
    false
}

fn decode_double_string(raw: &str) -> Option<String> {
    if raw.len() < 2 || !raw.starts_with('\"') || !raw.ends_with('\"') {
        return None;
    }
    let mut out = String::new();
    let mut chars = raw[1..raw.len() - 1].chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let next = chars.next()?;
            match next {
                '\\' => out.push('\\'),
                '"' => out.push('"'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                '$' => out.push('$'),
                _ => return None,
            }
        } else {
            out.push(ch);
        }
    }
    Some(out)
}

fn decode_triple_string(raw: &str) -> Option<String> {
    if raw.len() < 6 || !raw.starts_with("\"\"\"") || !raw.ends_with("\"\"\"") {
        return None;
    }
    let mut inner = &raw[3..raw.len() - 3];
    if inner.starts_with("\r\n") {
        inner = &inner[2..];
    } else if inner.starts_with('\n') {
        inner = &inner[1..];
    }
    if inner.ends_with("\r\n") {
        inner = &inner[..inner.len() - 2];
    } else if inner.ends_with('\n') {
        inner = &inner[..inner.len() - 1];
    }
    Some(inner.to_string())
}

#[derive(Clone)]
struct KeywordLiteral {
    canonical: String,
    has_namespace: bool,
}

fn parse_keyword_literal(text: &str, node: tree_sitter::Node<'_>) -> Option<KeywordLiteral> {
    if node.kind() != "keyword" {
        return None;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "identifier" => {
                let ident = node_text(text, child);
                return keyword_from_identifier(ident);
            }
            "string" => {
                let value = parse_string_literal(text, child)?;
                return keyword_from_string(&value);
            }
            _ => {}
        }
    }
    None
}

fn parse_keyword_like(text: &str, node: tree_sitter::Node<'_>) -> Option<KeywordLiteral> {
    if node.kind() == "keyword" {
        return parse_keyword_literal(text, node);
    }
    if node.kind() != "tagged" {
        return None;
    }
    let constructor = direct_child_by_kind(node, "constructor")?;
    if node_text(text, constructor) != "Keyword" {
        return None;
    }
    let args = constructor_value_args(node)?;
    if args.len() != 1 {
        return None;
    }
    let arg_node = unwrap_value_node(args[0]);
    if arg_node.kind() != "string" {
        return None;
    }
    let value = parse_string_literal(text, arg_node)?;
    keyword_from_string(&value)
}

fn keyword_from_identifier(ident: &str) -> Option<KeywordLiteral> {
    let Some(idx) = ident.find('_') else {
        return Some(KeywordLiteral {
            canonical: ident.to_string(),
            has_namespace: false,
        });
    };
    if idx == 0 || idx + 1 >= ident.len() {
        return None;
    }
    let namespace = &ident[..idx];
    let name = &ident[idx + 1..];
    if namespace.is_empty() || name.is_empty() {
        return None;
    }
    Some(KeywordLiteral {
        canonical: format!("{}/{}", namespace, name),
        has_namespace: true,
    })
}

fn keyword_from_string(value: &str) -> Option<KeywordLiteral> {
    if value.is_empty() {
        return None;
    }
    let mut parts = value.split('/');
    let namespace = parts.next()?;
    let name = parts.next();
    if name.is_none() {
        return Some(KeywordLiteral {
            canonical: value.to_string(),
            has_namespace: false,
        });
    }
    if parts.next().is_some() {
        return None;
    }
    let name = name?;
    if namespace.is_empty() || name.is_empty() {
        return None;
    }
    Some(KeywordLiteral {
        canonical: value.to_string(),
        has_namespace: true,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MapKeyKind {
    String,
    Keyword,
}

struct MapKeyInfo {
    name: String,
    kind: MapKeyKind,
    range: Range,
}

fn map_entry_key_info<'a>(text: &str, entry: tree_sitter::Node<'a>) -> Option<MapKeyInfo> {
    let map_key_node = direct_child_by_kind(entry, "map_key")?;
    let mut cursor = map_key_node.walk();
    let key_node: tree_sitter::Node<'a> = map_key_node.children(&mut cursor).next()?;
    let (name, kind) = match key_node.kind() {
        "string" => {
            let value = parse_string_literal(text, key_node)?;
            (value, MapKeyKind::String)
        }
        "keyword" => {
            let keyword = parse_keyword_literal(text, key_node)?;
            (keyword.canonical, MapKeyKind::Keyword)
        }
        "identifier" | "lower_identifier" | "keyword_identifier" => {
            (node_text(text, key_node).to_string(), MapKeyKind::Keyword)
        }
        _ => return None,
    };
    let range = byte_range_to_lsp_range(text, key_node.start_byte(), key_node.end_byte());
    Some(MapKeyInfo { name, kind, range })
}

fn number_kind(node: tree_sitter::Node<'_>) -> Option<&'static str> {
    if node.kind() != "number" {
        return None;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        if matches!(kind, "int" | "uint" | "bigint" | "float32" | "float64") {
            return Some(kind);
        }
    }
    None
}

fn parse_int_literal(text: &str, node: tree_sitter::Node<'_>) -> Option<i128> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "int" {
            return node_text(text, child).parse::<i128>().ok();
        }
    }
    None
}

fn parse_uint_literal(text: &str, node: tree_sitter::Node<'_>) -> Option<u128> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "uint" {
            let raw = node_text(text, child);
            let trimmed = raw.strip_suffix('u')?;
            return trimmed.parse::<u128>().ok();
        }
    }
    None
}

const MAX_JS_SAFE_INTEGER: u128 = 9_007_199_254_740_991;

fn canonical_decimal_string(input: &str) -> Result<String, DecimalError> {
    if input.is_empty() || !input.is_ascii() {
        return Err(DecimalError::Invalid);
    }
    if input.starts_with('+') {
        return Err(DecimalError::Invalid);
    }
    if input.contains('e') || input.contains('E') {
        return Err(DecimalError::Invalid);
    }
    if input.chars().any(|ch| ch.is_whitespace()) {
        return Err(DecimalError::Invalid);
    }
    if input
        .chars()
        .any(|ch| !(ch.is_ascii_digit() || ch == '-' || ch == '.'))
    {
        return Err(DecimalError::Invalid);
    }
    let (sign, rest) = if let Some(stripped) = input.strip_prefix('-') {
        ("-", stripped)
    } else {
        ("", input)
    };
    if rest.is_empty() {
        return Err(DecimalError::Invalid);
    }
    let mut parts = rest.split('.');
    let int_part = parts.next().unwrap_or_default();
    let frac_part = parts.next();
    if parts.next().is_some() {
        return Err(DecimalError::Invalid);
    }
    if int_part.is_empty() {
        return Err(DecimalError::Invalid);
    }
    if !int_part.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(DecimalError::Invalid);
    }
    let frac_part = match frac_part {
        Some(part) => {
            if part.is_empty() {
                return Err(DecimalError::Invalid);
            }
            if !part.chars().all(|ch| ch.is_ascii_digit()) {
                return Err(DecimalError::Invalid);
            }
            Some(part)
        }
        None => None,
    };
    let int_trimmed = int_part.trim_start_matches('0');
    let int_norm = if int_trimmed.is_empty() {
        "0"
    } else {
        int_trimmed
    };
    let frac_norm = frac_part
        .map(|part| part.trim_end_matches('0'))
        .filter(|part| !part.is_empty());
    let is_zero = int_norm == "0" && frac_norm.is_none();
    let sign_norm = if is_zero { "" } else { sign };
    let mut canonical = String::new();
    canonical.push_str(sign_norm);
    canonical.push_str(int_norm);
    if let Some(frac) = frac_norm {
        canonical.push('.');
        canonical.push_str(frac);
    }
    Ok(canonical)
}

#[derive(Debug)]
enum DecimalError {
    Invalid,
}

enum ArityRule {
    Exact(usize),
    Min(usize),
}

enum InstantValidity {
    Canonical,
    NonCanonical,
    Invalid,
}

fn validate_instant_string(input: &str) -> InstantValidity {
    if input.is_empty() || !input.is_ascii() {
        return InstantValidity::Invalid;
    }
    if input.chars().any(|ch| ch.is_whitespace()) {
        return InstantValidity::Invalid;
    }
    let bytes = input.as_bytes();
    if bytes.len() < 20 || *bytes.last().unwrap() != b'Z' {
        return InstantValidity::Invalid;
    }
    if bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return InstantValidity::Invalid;
    }
    let Some(year) = parse_digits(bytes, 0, 4) else {
        return InstantValidity::Invalid;
    };
    let Some(month) = parse_digits(bytes, 5, 2) else {
        return InstantValidity::Invalid;
    };
    let Some(day) = parse_digits(bytes, 8, 2) else {
        return InstantValidity::Invalid;
    };
    let Some(hour) = parse_digits(bytes, 11, 2) else {
        return InstantValidity::Invalid;
    };
    let Some(minute) = parse_digits(bytes, 14, 2) else {
        return InstantValidity::Invalid;
    };
    let Some(second) = parse_digits(bytes, 17, 2) else {
        return InstantValidity::Invalid;
    };
    if month == 0 || month > 12 {
        return InstantValidity::Invalid;
    }
    if hour > 23 || minute > 59 || second > 59 {
        return InstantValidity::Invalid;
    }
    let max_day = days_in_month(year as i32, month);
    if day == 0 || day > max_day {
        return InstantValidity::Invalid;
    }
    let mut non_canonical = false;
    match bytes.get(19) {
        Some(b'Z') => {
            if bytes.len() != 20 {
                return InstantValidity::Invalid;
            }
        }
        Some(b'.') => {
            if bytes.len() < 22 {
                return InstantValidity::Invalid;
            }
            let frac = &bytes[20..bytes.len() - 1];
            if frac.len() > 9 || frac.is_empty() {
                return InstantValidity::Invalid;
            }
            if !frac.iter().all(|b| b.is_ascii_digit()) {
                return InstantValidity::Invalid;
            }
            if *frac.last().unwrap() == b'0' {
                non_canonical = true;
            }
        }
        _ => return InstantValidity::Invalid,
    }
    if non_canonical {
        InstantValidity::NonCanonical
    } else {
        InstantValidity::Canonical
    }
}

fn parse_digits(bytes: &[u8], start: usize, len: usize) -> Option<u32> {
    if start + len > bytes.len() {
        return None;
    }
    let mut value = 0u32;
    for &b in &bytes[start..start + len] {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value * 10 + (b - b'0') as u32;
    }
    Some(value)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn push_semantic_diagnostic(
    diagnostics: &mut Vec<Diagnostic>,
    range: Range,
    severity: DiagnosticSeverity,
    code: &'static str,
    message: &str,
) {
    diagnostics.push(Diagnostic {
        range,
        severity: Some(severity),
        code: Some(NumberOrString::String(code.to_string())),
        code_description: None,
        source: Some("rulia-lsp".to_string()),
        message: message.to_string(),
        related_information: None,
        tags: None,
        data: None,
    });
}

fn collect_leaf_error_nodes<'a>(
    node: tree_sitter::Node<'a>,
    out: &mut Vec<tree_sitter::Node<'a>>,
) -> bool {
    let mut cursor = node.walk();
    let mut has_error_descendant = false;
    for child in node.children(&mut cursor) {
        if collect_leaf_error_nodes(child, out) {
            has_error_descendant = true;
        }
    }
    let is_error = node.is_error() || node.is_missing();
    if is_error && !has_error_descendant {
        out.push(node);
    }
    is_error || has_error_descendant
}

fn byte_range_to_lsp_range(text: &str, start: usize, end: usize) -> Range {
    let start_byte = start.min(text.len());
    let end_byte = end.max(start_byte).min(text.len());
    let start_pos = byte_offset_to_utf16_position(text, start_byte);
    let end_pos = byte_offset_to_utf16_position(text, end_byte);
    Range::new(
        Position::new(start_pos.0, start_pos.1),
        Position::new(end_pos.0, end_pos.1),
    )
}

fn byte_offset_to_utf16_position(text: &str, byte: usize) -> (u32, u32) {
    let mut line_start = 0usize;
    let mut line = 0u32;
    let mut byte_index = byte.min(text.len());
    while byte_index > 0 && !text.is_char_boundary(byte_index) {
        byte_index -= 1;
    }
    for (idx, b) in text.as_bytes().iter().enumerate().take(byte_index) {
        if *b == b'\n' {
            line += 1;
            line_start = idx + 1;
        }
    }
    let slice = &text[line_start..byte_index];
    let col = slice.encode_utf16().count() as u32;
    (line, col)
}

#[derive(Hash, Eq, PartialEq)]
struct DiagnosticKey {
    start_line: u32,
    start_char: u32,
    end_line: u32,
    end_char: u32,
    message: &'static str,
}

impl DiagnosticKey {
    fn new(range: &Range, message: &'static str) -> Self {
        Self {
            start_line: range.start.line,
            start_char: range.start.character,
            end_line: range.end.line,
            end_char: range.end.character,
            message,
        }
    }
}

#[tokio::main]
async fn main() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let (service, socket) = LspService::new(Backend::new);
    Server::new(stdin, stdout, socket).serve(service).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code_str(diag: &Diagnostic) -> Option<&str> {
        match diag.code.as_ref() {
            Some(NumberOrString::String(code)) => Some(code.as_str()),
            _ => None,
        }
    }

    #[test]
    fn format_import_preserved() {
        let input = "import   \"config.rjl\"  sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let formatted = compute_format(input).expect("formatting should succeed");
        let expected = rulia_fmt::format(input).expect("rulia-fmt should succeed");
        assert_eq!(formatted, expected);
        assert!(formatted.contains("import"));
        assert!(formatted.contains("sha256:"));
    }

    #[test]
    fn format_new_preserved() {
        let input = " @new( :uuid ) ";
        let formatted = compute_format(input).expect("formatting should succeed");
        let expected = rulia_fmt::format(input).expect("rulia-fmt should succeed");
        assert_eq!(formatted, expected);
        assert!(formatted.contains("@new(:uuid)"));
    }

    #[test]
    fn format_invalid_returns_none() {
        let input = "(";
        assert!(compute_format(input).is_none());
    }

    #[test]
    fn utf16_position_counts_unicode() {
        let text = "a💙b\nc";
        assert_eq!(byte_offset_to_utf16_position(text, 0), (0, 0));
        assert_eq!(byte_offset_to_utf16_position(text, 1), (0, 1));
        assert_eq!(byte_offset_to_utf16_position(text, 5), (0, 3));
        assert_eq!(byte_offset_to_utf16_position(text, 6), (0, 4));
        assert_eq!(byte_offset_to_utf16_position(text, 7), (1, 0));
        assert_eq!(byte_offset_to_utf16_position(text, text.len()), (1, 1));
    }

    #[test]
    fn diagnostics_missing_token_range() {
        let input = "[1, 2";
        let diagnostics = compute_diagnostics(input);
        assert_eq!(diagnostics.len(), 1);
        let diag = &diagnostics[0];
        assert_eq!(diag.source.as_deref(), Some("tree-sitter"));
        assert_eq!(diag.message, "missing token");
        assert_eq!(diag.range.start.line, 0);
        assert_eq!(diag.range.start.character, 5);
        assert_eq!(diag.range.end.line, 0);
        assert_eq!(diag.range.end.character, 5);
    }

    #[test]
    fn diagnostics_unicode_range() {
        let input = "[\"💙\"";
        let diagnostics = compute_diagnostics(input);
        assert_eq!(diagnostics.len(), 1);
        let diag = &diagnostics[0];
        assert_eq!(diag.source.as_deref(), Some("tree-sitter"));
        assert_eq!(diag.message, "missing token");
        assert_eq!(diag.range.start.line, 0);
        assert_eq!(diag.range.start.character, 5);
        assert_eq!(diag.range.end.line, 0);
        assert_eq!(diag.range.end.character, 5);
    }

    #[test]
    fn diagnostics_clear_on_valid() {
        let diagnostics = compute_diagnostics("nil");
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn diagnostics_gated_on_syntax_errors() {
        let input = "Tagged(\"decimal\", \"01\") [";
        let diagnostics = compute_diagnostics(input);
        assert!(!diagnostics.is_empty());
        assert!(diagnostics
            .iter()
            .all(|diag| diag.source.as_deref() == Some("tree-sitter")));
        assert!(diagnostics.iter().all(|diag| diag.code.is_none()));
    }

    #[test]
    fn decimal_noncanonical_reports_utf16_range() {
        let input = "[\"💙\", Tagged(\"decimal\", \"01\")]";
        let diagnostics = compute_diagnostics(input);
        assert_eq!(diagnostics.len(), 1);
        let diag = &diagnostics[0];
        assert_eq!(code_str(diag), Some("DECIMAL_NONCANONICAL"));
        assert_eq!(diag.range.start.line, 0);
        assert_eq!(diag.range.start.character, 25);
        assert_eq!(diag.range.end.line, 0);
        assert_eq!(diag.range.end.character, 29);
    }

    #[test]
    fn path_invalid_segments_reported() {
        let input = "Tagged(\"path\", [\"ok\", -1, 1.2])";
        let diagnostics = compute_diagnostics(input);
        assert_eq!(diagnostics.len(), 2);
        for diag in diagnostics {
            assert_eq!(code_str(&diag), Some("PATH_INVALID_SEGMENT"));
        }
    }

    #[test]
    fn expr_invalid_arity_reported() {
        let input = "Tagged(\"expr\", [:and, true])";
        let diagnostics = compute_diagnostics(input);
        assert_eq!(diagnostics.len(), 1);
        let diag = &diagnostics[0];
        assert_eq!(code_str(diag), Some("EXPR_INVALID_ARITY"));
    }

    #[test]
    fn instant_noncanonical_reported() {
        let input = "Instant(\"2025-01-01T00:00:00.0Z\")";
        let diagnostics = compute_diagnostics(input);
        assert_eq!(diagnostics.len(), 1);
        let diag = &diagnostics[0];
        assert_eq!(code_str(diag), Some("INSTANT_NONCANONICAL"));
    }

    #[test]
    fn valid_file_has_no_diagnostics() {
        let input = "[Tagged(\"decimal\", \"1.23\"), Tagged(\"path\", [\"user\", 0, :user_name]), Tagged(\"expr\", [Keyword(\"==\"), 1, 1]), Instant(\"2025-01-01T00:00:00Z\"), (\"kind\" = \"example\", \"payload\" = nil)]";
        let diagnostics = compute_diagnostics(input);
        assert!(diagnostics.is_empty());
    }
}
