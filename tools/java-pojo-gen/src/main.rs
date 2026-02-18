use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() != 2 {
        return Err(
            "usage: cargo run --manifest-path tools/java-pojo-gen/Cargo.toml -- <schema.json> <output-dir>"
                .to_string(),
        );
    }

    let schema_path = PathBuf::from(&args[0]);
    let out_dir = PathBuf::from(&args[1]);

    let schema_raw = fs::read_to_string(&schema_path)
        .map_err(|err| format!("failed to read schema {}: {err}", schema_path.display()))?;
    let schema: Schema =
        serde_json::from_str(&schema_raw).map_err(|err| format!("invalid schema json: {err}"))?;

    validate_schema(&schema)?;

    let outputs = render_all(&schema)?;
    for output in outputs {
        let java_path = java_output_path(&out_dir, &schema.package, &output.class_name);
        if let Some(parent) = java_path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                format!("failed to create output dir {}: {err}", parent.display())
            })?;
        }
        fs::write(&java_path, output.source)
            .map_err(|err| format!("failed to write {}: {err}", java_path.display()))?;
        println!("generated {}", java_path.display());
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct Schema {
    package: String,
    #[serde(default)]
    class_name: Option<String>,
    #[serde(default)]
    fields: Vec<Field>,
    #[serde(default)]
    templates: Vec<TemplateSpec>,
}

#[derive(Debug, Deserialize)]
struct Field {
    name: String,
    java_type: String,
    #[serde(default)]
    json_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TemplateSpec {
    template: String,
    class_name: String,
}

#[derive(Debug)]
struct OutputFile {
    class_name: String,
    source: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FieldKind {
    Boolean,
    Int,
    Long,
    String,
}

impl Field {
    fn json_key(&self) -> &str {
        self.json_key.as_deref().unwrap_or(&self.name)
    }

    fn kind(&self) -> Result<FieldKind, String> {
        match self.java_type.as_str() {
            "boolean" => Ok(FieldKind::Boolean),
            "int" => Ok(FieldKind::Int),
            "long" => Ok(FieldKind::Long),
            "String" => Ok(FieldKind::String),
            other => Err(format!(
                "unsupported java_type '{}' for field '{}' (supported: boolean,int,long,String)",
                other, self.name
            )),
        }
    }
}

fn validate_schema(schema: &Schema) -> Result<(), String> {
    if schema.package.trim().is_empty() {
        return Err("schema.package must be non-empty".to_string());
    }

    let has_struct = schema.class_name.as_ref().is_some() || !schema.fields.is_empty();
    let has_templates = !schema.templates.is_empty();
    if !has_struct && !has_templates {
        return Err(
            "schema must provide either (class_name + fields) and/or templates".to_string(),
        );
    }

    let mut class_names = HashSet::new();

    if has_struct {
        let class_name = schema
            .class_name
            .as_ref()
            .ok_or("schema.class_name must be set when schema.fields is used")?;
        if class_name.trim().is_empty() {
            return Err("schema.class_name must be non-empty".to_string());
        }
        if schema.fields.is_empty() {
            return Err("schema.fields must be non-empty when class_name is set".to_string());
        }
        class_names.insert(class_name.clone());

        let mut names = HashSet::new();
        let mut keys = HashSet::new();
        for field in &schema.fields {
            if !names.insert(field.name.clone()) {
                return Err(format!("duplicate field name: {}", field.name));
            }
            if !keys.insert(field.json_key().to_string()) {
                return Err(format!("duplicate json_key: {}", field.json_key()));
            }
            let _ = field.kind()?;
        }
    }

    for template in &schema.templates {
        if template.class_name.trim().is_empty() {
            return Err("template.class_name must be non-empty".to_string());
        }
        if !class_names.insert(template.class_name.clone()) {
            return Err(format!("duplicate class_name: {}", template.class_name));
        }
        match template.template.as_str() {
            "canon_bytes_v1" | "stress_record_v1" => {}
            other => {
                return Err(format!(
                    "unsupported template '{}' (supported: canon_bytes_v1, stress_record_v1)",
                    other
                ));
            }
        }
    }

    Ok(())
}

fn java_output_path(out_dir: &Path, package: &str, class_name: &str) -> PathBuf {
    let mut path = out_dir.to_path_buf();
    for segment in package.split('.') {
        path.push(segment);
    }
    path.push(format!("{class_name}.java"));
    path
}

fn render_all(schema: &Schema) -> Result<Vec<OutputFile>, String> {
    let mut out = Vec::new();

    if let Some(class_name) = &schema.class_name {
        out.push(OutputFile {
            class_name: class_name.clone(),
            source: render_struct_java(schema, class_name, &schema.fields)?,
        });
    }

    for template in &schema.templates {
        out.push(OutputFile {
            class_name: template.class_name.clone(),
            source: render_template_java(schema, template)?,
        });
    }

    Ok(out)
}

fn render_struct_java(
    schema: &Schema,
    class_name: &str,
    fields: &[Field],
) -> Result<String, String> {
    let mut fields_sorted: Vec<&Field> = fields.iter().collect();
    fields_sorted.sort_by(|a, b| a.json_key().cmp(b.json_key()));

    let ctor_params = fields
        .iter()
        .map(|f| format!("{} {}", f.java_type, f.name))
        .collect::<Vec<_>>()
        .join(", ");

    let mut out = String::new();
    out.push_str("// AUTO-GENERATED BY tools/java-pojo-gen. DO NOT EDIT.\n");
    out.push_str("// The canonical writer emits object keys in lexicographic order for deterministic output.\n");
    out.push_str(&format!("package {};\n\n", schema.package));
    out.push_str("import java.nio.charset.StandardCharsets;\n\n");
    out.push_str(&format!("public final class {} {{\n", class_name));

    for field in fields {
        out.push_str(&format!(
            "    private final {} {};\n",
            field.java_type, field.name
        ));
    }
    out.push('\n');

    out.push_str(&format!("    public {}({}) {{\n", class_name, ctor_params));
    for field in fields {
        out.push_str(&format!("        this.{0} = {0};\n", field.name));
    }
    out.push_str("    }\n\n");

    for field in fields {
        out.push_str(&format!(
            "    public {} {}() {{\n        return {};\n    }}\n\n",
            field.java_type, field.name, field.name
        ));
    }

    out.push_str("    public byte[] toCanonicalUtf8() {\n");
    out.push_str("        StringBuilder sb = new StringBuilder(128);\n");
    out.push_str("        appendCanonicalJson(sb);\n");
    out.push_str("        return sb.toString().getBytes(StandardCharsets.UTF_8);\n");
    out.push_str("    }\n\n");

    out.push_str("    public void appendCanonicalJson(StringBuilder sb) {\n");
    out.push_str("        sb.append('{');\n");
    for (idx, field) in fields_sorted.iter().enumerate() {
        if idx > 0 {
            out.push_str("        sb.append(',');\n");
        }
        let key = escape_java_string(field.json_key());
        out.push_str(&format!("        sb.append(\"\\\"{}\\\":\");\n", key));

        match field.kind()? {
            FieldKind::Boolean => {
                out.push_str(&format!(
                    "        sb.append(this.{0} ? \"true\" : \"false\");\n",
                    field.name
                ));
            }
            FieldKind::Int | FieldKind::Long => {
                out.push_str(&format!("        sb.append(this.{});\n", field.name));
            }
            FieldKind::String => {
                out.push_str(&format!(
                    "        appendJsonString(sb, this.{});\n",
                    field.name
                ));
            }
        }
    }
    out.push_str("        sb.append('}');\n");
    out.push_str("    }\n\n");

    out.push_str(&append_json_string_helper());
    out.push_str("}\n");
    Ok(out)
}

fn render_template_java(schema: &Schema, template: &TemplateSpec) -> Result<String, String> {
    match template.template.as_str() {
        "canon_bytes_v1" => Ok(render_template_canon_bytes(schema, template)),
        "stress_record_v1" => Ok(render_template_stress_record(schema, template)),
        other => Err(format!(
            "unsupported template '{}': internal validation bug",
            other
        )),
    }
}

fn render_template_canon_bytes(schema: &Schema, template: &TemplateSpec) -> String {
    let mut out = String::new();
    out.push_str("// AUTO-GENERATED BY tools/java-pojo-gen. DO NOT EDIT.\n");
    out.push_str(&format!("package {};\n\n", schema.package));
    out.push_str("import com.rulia.demo.CanonJson;\n\n");
    out.push_str(&format!(
        "public final class {} implements CanonJson.CanonicalValue {{\n",
        template.class_name
    ));
    out.push_str("    private final byte[] canonicalUtf8;\n\n");
    out.push_str(&format!(
        "    public {}(byte[] canonicalUtf8) {{\n",
        template.class_name
    ));
    out.push_str("        this.canonicalUtf8 = canonicalUtf8;\n");
    out.push_str("    }\n\n");
    out.push_str("    @Override\n");
    out.push_str("    public byte[] canonicalUtf8() {\n");
    out.push_str("        return canonicalUtf8;\n");
    out.push_str("    }\n");
    out.push_str("}\n");
    out
}

fn render_template_stress_record(schema: &Schema, template: &TemplateSpec) -> String {
    let mut out = String::new();
    out.push_str("// AUTO-GENERATED BY tools/java-pojo-gen. DO NOT EDIT.\n");
    out.push_str(
        "// This template materializes canonical UTF-8 once, then reuses bytes in hot loops.\n",
    );
    out.push_str(&format!("package {};\n\n", schema.package));
    out.push_str("import com.rulia.demo.CanonJson;\n");
    out.push_str("import java.nio.charset.StandardCharsets;\n\n");
    out.push_str(&format!(
        "public final class {} implements CanonJson.CanonicalValue {{\n",
        template.class_name
    ));
    out.push_str("    private final byte[] canonicalUtf8;\n\n");
    out.push_str(&format!("    public {}(\n", template.class_name));
    out.push_str("            int caseValue,\n");
    out.push_str("            int sourceIndex,\n");
    out.push_str("            byte[] payloadCanonicalUtf8,\n");
    out.push_str("            boolean flag,\n");
    out.push_str("            long seq,\n");
    out.push_str("            String text,\n");
    out.push_str("            int neg,\n");
    out.push_str("            long big,\n");
    out.push_str("            int small) {\n");
    out.push_str(
        "        String payloadJson = new String(payloadCanonicalUtf8, StandardCharsets.UTF_8);\n",
    );
    out.push_str("        StringBuilder sb = new StringBuilder(payloadJson.length() * 2 + 192);\n");
    out.push_str("        sb.append('{');\n");
    out.push_str("        sb.append(\"\\\"case\\\":\").append(caseValue);\n");
    out.push_str("        sb.append(\",\\\"echo\\\":[\");\n");
    out.push_str("        sb.append(payloadJson);\n");
    out.push_str("        sb.append(\",{\\\"flag\\\":\").append(flag ? \"true\" : \"false\");\n");
    out.push_str("        sb.append(\",\\\"seq\\\":\").append(seq);\n");
    out.push_str("        sb.append(\",\\\"text\\\":\");\n");
    out.push_str("        appendJsonString(sb, text);\n");
    out.push_str("        sb.append(\"}]\");\n");
    out.push_str("        sb.append(\",\\\"kind\\\":\\\"stress\\\"\");\n");
    out.push_str("        sb.append(\",\\\"metrics\\\":{\\\"big\\\":\").append(big);\n");
    out.push_str("        sb.append(\",\\\"neg\\\":\").append(neg);\n");
    out.push_str("        sb.append(\",\\\"small\\\":\").append(small).append('}');\n");
    out.push_str("        sb.append(\",\\\"payload\\\":\").append(payloadJson);\n");
    out.push_str("        sb.append(\",\\\"source_index\\\":\").append(sourceIndex);\n");
    out.push_str("        sb.append('}');\n");
    out.push_str("        this.canonicalUtf8 = sb.toString().getBytes(StandardCharsets.UTF_8);\n");
    out.push_str("    }\n\n");
    out.push_str("    @Override\n");
    out.push_str("    public byte[] canonicalUtf8() {\n");
    out.push_str("        return canonicalUtf8;\n");
    out.push_str("    }\n\n");
    out.push_str(&append_json_string_helper());
    out.push_str("}\n");
    out
}

fn append_json_string_helper() -> String {
    let mut out = String::new();
    out.push_str("    private static void appendJsonString(StringBuilder sb, String value) {\n");
    out.push_str("        if (value == null) {\n");
    out.push_str("            sb.append(\"null\");\n");
    out.push_str("            return;\n");
    out.push_str("        }\n");
    out.push_str("        sb.append('\\\"');\n");
    out.push_str("        for (int i = 0; i < value.length(); i++) {\n");
    out.push_str("            char ch = value.charAt(i);\n");
    out.push_str("            switch (ch) {\n");
    out.push_str("                case '\\\\' -> sb.append(\"\\\\\\\\\");\n");
    out.push_str("                case '\\\"' -> sb.append(\"\\\\\\\"\");\n");
    out.push_str("                case '\\b' -> sb.append(\"\\\\b\");\n");
    out.push_str("                case '\\f' -> sb.append(\"\\\\f\");\n");
    out.push_str("                case '\\n' -> sb.append(\"\\\\n\");\n");
    out.push_str("                case '\\r' -> sb.append(\"\\\\r\");\n");
    out.push_str("                case '\\t' -> sb.append(\"\\\\t\");\n");
    out.push_str("                default -> {\n");
    out.push_str("                    if (ch < 0x20) {\n");
    out.push_str("                        sb.append(\"\\\\u\");\n");
    out.push_str("                        String hex = Integer.toHexString(ch);\n");
    out.push_str(
        "                        for (int j = hex.length(); j < 4; j++) sb.append('0');\n",
    );
    out.push_str("                        sb.append(hex);\n");
    out.push_str("                    } else {\n");
    out.push_str("                        sb.append(ch);\n");
    out.push_str("                    }\n");
    out.push_str("                }\n");
    out.push_str("            }\n");
    out.push_str("        }\n");
    out.push_str("        sb.append('\\\"');\n");
    out.push_str("    }\n");
    out
}

fn escape_java_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\\\\\"),
            '"' => out.push_str("\\\\\""),
            '\n' => out.push_str("\\\\n"),
            '\r' => out.push_str("\\\\r"),
            '\t' => out.push_str("\\\\t"),
            _ => out.push(ch),
        }
    }
    out
}
