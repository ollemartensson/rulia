use std::collections::HashSet;

use proptest::prelude::*;
use rulia::{text, Annotation, Keyword, Symbol, TaggedValue, Value};

const MAX_DEPTH: u32 = 4;
const MAX_COLLECTION_LEN: usize = 4;
const MAX_STRING_LEN: usize = 32;
const MAX_BYTES_LEN: usize = 32;
const MAX_IDENT_LEN: usize = 12;

fn ident_part() -> impl Strategy<Value = String> {
    let first = prop_oneof![
        Just('_'),
        prop::char::range('a', 'z'),
        prop::char::range('A', 'Z'),
    ];
    let rest_char = prop_oneof![
        Just('_'),
        prop::char::range('a', 'z'),
        prop::char::range('A', 'Z'),
        prop::char::range('0', '9'),
    ];
    (first, prop::collection::vec(rest_char, 0..=MAX_IDENT_LEN)).prop_map(|(first, rest)| {
        let mut out = String::new();
        out.push(first);
        for ch in rest {
            out.push(ch);
        }
        out
    })
}

fn tag_component() -> impl Strategy<Value = String> {
    let first = prop::char::range('a', 'z');
    let rest_char = prop_oneof![
        prop::char::range('a', 'z'),
        prop::char::range('0', '9'),
        Just('-'),
    ];
    (first, prop::collection::vec(rest_char, 0..=MAX_IDENT_LEN)).prop_map(|(first, rest)| {
        let mut out = String::new();
        out.push(first);
        for ch in rest {
            out.push(ch);
        }
        out
    })
}

fn ident_part_no_underscore() -> impl Strategy<Value = String> {
    ident_part().prop_filter("namespace must not contain underscore", |value| {
        !value.contains('_')
    })
}

fn tag_symbol_strategy() -> impl Strategy<Value = Symbol> {
    tag_component().prop_map(|name| Symbol::new(None, format!("{name}-tag")))
}

fn keyword_strategy() -> impl Strategy<Value = Keyword> {
    (prop::option::of(ident_part()), ident_part()).prop_map(|(ns, name)| Keyword::new(ns, name))
}

fn meta_keyword_strategy() -> impl Strategy<Value = Keyword> {
    (prop::option::of(ident_part_no_underscore()), ident_part())
        .prop_map(|(ns, name)| Keyword::new(ns, name))
        .prop_filter("exclude doc keyword for canonical text", |kw| {
            kw.name() != "doc"
        })
}

fn string_strategy() -> impl Strategy<Value = String> {
    let ch = prop_oneof![
        prop::char::range('a', 'z'),
        prop::char::range('A', 'Z'),
        prop::char::range('0', '9'),
        Just(' '),
        Just('_'),
        Just('-'),
        Just('/'),
        Just('\n'),
        Just('\r'),
        Just('\t'),
        Just('\\'),
        Just('"'),
        Just('$'),
    ];
    prop::collection::vec(ch, 0..=MAX_STRING_LEN).prop_map(|chars| chars.into_iter().collect())
}

fn bytes_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=MAX_BYTES_LEN)
}

fn map_key_strategy() -> impl Strategy<Value = Value> {
    prop_oneof![
        keyword_strategy().prop_map(Value::Keyword),
        string_strategy().prop_map(Value::String),
    ]
}

fn leaf_value_strategy() -> impl Strategy<Value = Value> + Clone {
    prop_oneof![
        Just(Value::Nil),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::Int),
        any::<u64>().prop_map(Value::UInt),
        string_strategy().prop_map(Value::String),
        bytes_strategy().prop_map(Value::Bytes),
        keyword_strategy().prop_map(Value::Keyword),
    ]
}

fn canonical_key(value: &Value) -> String {
    text::to_canonical_string(value)
}

fn map_entries_strategy(
    value_strategy: impl Strategy<Value = Value> + Clone,
) -> impl Strategy<Value = Vec<(Value, Value)>> {
    prop::collection::vec((map_key_strategy(), value_strategy), 0..=MAX_COLLECTION_LEN).prop_map(
        |entries| {
            let mut seen = HashSet::new();
            let mut unique = Vec::new();
            for (key, value) in entries {
                if seen.insert(key.clone()) {
                    unique.push((key, value));
                }
            }
            unique.sort_by(|a, b| canonical_key(&a.0).cmp(&canonical_key(&b.0)));
            unique
        },
    )
}

fn metadata_entries_strategy() -> impl Strategy<Value = Vec<(Value, Value)>> {
    let entries = prop::collection::vec(
        (
            meta_keyword_strategy().prop_map(Value::Keyword),
            leaf_value_strategy(),
        ),
        0..=MAX_COLLECTION_LEN,
    );

    entries.prop_map(|entries| {
        let mut seen = HashSet::new();
        let mut unique = Vec::new();
        for (key, value) in entries {
            if seen.insert(key.clone()) {
                unique.push((key, value));
            }
        }
        unique.sort_by(|a, b| canonical_key(&a.0).cmp(&canonical_key(&b.0)));
        unique
    })
}

fn value_strategy() -> impl Strategy<Value = Value> {
    leaf_value_strategy().prop_recursive(MAX_DEPTH, 64, MAX_COLLECTION_LEN as u32, |inner| {
        let vector =
            prop::collection::vec(inner.clone(), 0..=MAX_COLLECTION_LEN).prop_map(Value::Vector);
        let map = map_entries_strategy(inner.clone()).prop_map(Value::Map);
        let tagged = (tag_symbol_strategy(), inner.clone())
            .prop_map(|(tag, value)| Value::Tagged(TaggedValue::new(tag, value)));
        let annotated_inner = inner
            .clone()
            .prop_filter("avoid nested annotations in canonical text", |value| {
                !matches!(value, Value::Annotated(_))
            });
        let annotated =
            (metadata_entries_strategy(), annotated_inner).prop_map(|(metadata, value)| {
                Value::Annotated(Box::new(Annotation::new(metadata, value)))
            });
        prop_oneof![vector, map, tagged, annotated]
    })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 96,
        max_shrink_iters: 256,
        .. ProptestConfig::default()
    })]

    #[test]
    fn canonical_text_idempotence(value in value_strategy()) {
        let rendered = text::to_canonical_string(&value);
        let reparsed = text::parse(&rendered).expect("parse canonical string");
        let rendered_again = text::to_canonical_string(&reparsed);
        prop_assert_eq!(rendered_again, rendered);
    }
}
