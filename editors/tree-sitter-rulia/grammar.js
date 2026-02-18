module.exports = grammar({
    name: "rulia",

    conflicts: ($) => [
        [$.value, $.docstring],
        [$.annotated, $.string],
        [$.annotated, $.value],
    ],

    extras: ($) => [/[\s\uFEFF\u2060\u200B\u200C\u200D]/, $.comment],

    word: ($) => $.identifier,

    rules: {
        source_file: ($) => optional($.value),

        comment: (_) => token(seq("#", /.*/)),

        value: ($) =>
            choice(
                $.import_stmt,
                $.let_expr,
                $.fn_expr,
                $.ns_macro,
                $.infix_expr,
                $.map,
                $.vector,
                $.set,
                $.tagged,
                $.call,
                $.generator,
                $.keyword,
                $.symbol,
                $.string,
                $.bytes,
                $.number,
                $.boolean,
                $.nil,
                $.annotated,
            ),

        nil: (_) => "nil",
        boolean: (_) => choice("true", "false"),

        number: ($) => choice($.float32, $.float64, $.bigint, $.uint, $.int),

        int: (_) => token(/-?\d+/),
        uint: (_) => token(/\d+u/),
        bigint: (_) => token(/-?\d+N/),
        float32: (_) => token(/-?\d+\.\d+(?:[eE][+-]?\d+)?f/),
        float64: (_) => token(/-?\d+\.\d+(?:[eE][+-]?\d+)?/),

        bytes: (_) => token(/0x\[[0-9A-Fa-f]*\]/),

        string: ($) => choice($.triple_string, $.double_string),

        triple_string: (_) => token(prec(2, /\"\"\"(.|\\n|\\r)*\"\"\"/)),

        double_string: ($) =>
            seq(
                '"',
                repeat(
                    choice(
                        $.escape_sequence,
                        $.interpolation,
                        $.string_content,
                    ),
                ),
                '"',
            ),

        string_content: (_) => token(prec(1, /[^"\\$]+/)),

        escape_sequence: (_) => token(seq("\\", /[\\"nrt$]/)),

        interpolation: (_) =>
            token(
                choice(
                    seq("$", /[A-Za-z_][A-Za-z0-9_]*/),
                    seq("$(", /[^)]*/, ")"),
                ),
            ),

        keyword: ($) =>
            choice(seq(":", $.identifier), seq("Keyword", "(", $.string, ")")),

        symbol: ($) =>
            choice(
                seq("'", $.identifier),
                seq("@?", $.identifier),
                "_",
                seq("Symbol", "(", $.string, ")"),
            ),

        vector: ($) =>
            seq(
                "[",
                optional(
                    seq($.value, repeat(seq(",", $.value)), optional(",")),
                ),
                "]",
            ),

        set: ($) => prec(3, seq("Set", "(", $.vector, ")")),

        map: ($) =>
            prec(
                2,
                seq(
                    "(",
                    optional(
                        seq(
                            $.map_entry,
                            repeat(seq(",", $.map_entry)),
                            optional(","),
                        ),
                    ),
                    ")",
                ),
            ),

        map_entry: ($) => seq($.map_key, "=", $.value),

        map_key: ($) =>
            choice(
                $.identifier,
                $.lower_identifier,
                $.keyword_identifier,
                $.constructor,
                $.keyword,
                $.string,
                "import",
                "let",
                "fn",
                "true",
                "false",
                "nil",
                "begin",
                "end",
            ),

        tagged: ($) =>
            choice(
                seq($.constructor, "(", optional($.args), ")"),
                seq("Tagged", "(", $.string, ",", $.value, ")"),
            ),

        call: ($) => seq($.lower_identifier, "(", optional($.args), ")"),

        args: ($) => choice($.map_args, $.value_args),

        map_args: ($) =>
            seq($.map_entry, repeat(seq(",", $.map_entry)), optional(",")),

        value_args: ($) =>
            seq($.value, repeat(seq(",", $.value)), optional(",")),

        let_expr: ($) => seq("let", choice($.binding, $.block), $.value),

        binding: ($) => seq(choice($.identifier, $.pattern), "=", $.value),

        block: ($) =>
            seq("{", repeat(seq($.binding, optional(choice(";", ",")))), "}"),

        pattern: ($) =>
            choice(
                seq(
                    "(",
                    $.identifier,
                    repeat(seq(",", $.identifier)),
                    optional(","),
                    ")",
                ),
                seq(
                    "[",
                    $.identifier,
                    repeat(seq(",", $.identifier)),
                    optional(","),
                    "]",
                ),
            ),

        fn_expr: ($) => seq("fn", "(", optional($.params), ")", "=>", $.value),

        params: ($) =>
            seq($.identifier, repeat(seq(",", $.identifier)), optional(",")),

        import_stmt: ($) => seq("import", $.string, optional($.hash_spec)),

        hash_spec: ($) => seq(choice("sha256", "blake3"), ":", $.hex_string),

        hex_string: (_) => token(/[0-9A-Fa-f]+/),

        annotated: ($) =>
            prec.dynamic(
                -1,
                choice(seq($.meta, $.value), seq($.docstring, $.value)),
            ),

        meta: ($) => seq("@meta", "(", optional($.map_args), ")"),

        docstring: ($) => $.string,

        generator: ($) =>
            choice(
                seq("@new", "(", $.keyword, ")"),
                seq("Generator", "(", $.keyword, ")"),
            ),

        ns_macro: ($) => seq("@ns", $.identifier, "begin", $.value, "end"),

        infix_expr: ($) =>
            prec(
                1,
                seq(
                    "(",
                    $.value,
                    $.infix_operator,
                    $.value,
                    repeat(seq($.infix_operator, $.value)),
                    ")",
                ),
            ),

        infix_operator: (_) =>
            token(
                choice(
                    "==",
                    "!=",
                    "<=",
                    ">=",
                    "<",
                    ">",
                    "in",
                    "contains",
                    "and",
                    "or",
                ),
            ),

        constructor: (_) => token(prec(2, /[A-Z][A-Za-z0-9_]*/)),
        identifier: (_) => token(/[A-Za-z_][A-Za-z0-9_]*/),
        lower_identifier: (_) => token(/[a-z_][A-Za-z0-9_]*/),
        keyword_identifier: (_) =>
            token(
                choice(
                    "import",
                    "let",
                    "fn",
                    "true",
                    "false",
                    "nil",
                    "begin",
                    "end",
                ),
            ),
    },
});
