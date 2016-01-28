<?php

$finder = Symfony\CS\Finder\DefaultFinder::create()
        ->in(__DIR__)
        ->exclude('src/config')
        ->ignoreDotFiles(true);

$header = <<<EOF
This file is part of jwt-auth

(c) Sean Tymon <tymon148@gmail.com>

For the full copyright and license information, please view the LICENSE
file that was distributed with this source code.
EOF;

Symfony\CS\Fixer\Contrib\HeaderCommentFixer::setHeader($header);

$fixers = [
    '-psr0',
    'alias_functions',
    'array_element_no_space_before_comma',
    'array_element_white_space_after_comma',
    'blankline_after_open_tag',
    'braces',
    'concat_with_spaces',
    'double_arrow_multiline_whitespaces',
    'duplicate_semicolon',
    'elseif',
    'empty_return',
    'encoding',
    'eof_ending',
    'extra_empty_lines',
    'function_call_space',
    'function_declaration',
    'function_typehint_space',
    'header_comment',
    'include',
    'indentation',
    'line_after_namespace',
    'linefeed',
    'list_commas',
    'logical_not_operators_with_successor_space',
    'lowercase_constants',
    'lowercase_keywords',
    'method_argument_space',
    'method_separation',
    'multiline_array_trailing_comma',
    'multiline_spaces_before_semicolon',
    'multiple_use',
    'namespace_no_leading_whitespace',
    'no_blank_lines_after_class_opening',
    'no_empty_lines_after_phpdocs',
    'object_operator',
    'operators_spaces',
    'parenthesis',
    'phpdoc_indent',
    'phpdoc_inline_tag',
    'phpdoc_no_access',
    'phpdoc_no_package',
    'phpdoc_scalar',
    'phpdoc_short_description',
    'phpdoc_summary',
    'phpdoc_to_comment',
    'phpdoc_trim',
    'phpdoc_type_to_var',
    'phpdoc_types',
    'phpdoc_var_without_name',
    'psr4',
    'remove_leading_slash_use',
    'remove_lines_between_uses',
    'return',
    'self_accessor',
    'short_array_syntax',
    'short_echo_tag',
    'short_tag',
    'single_array_no_trailing_comma',
    'single_line_after_imports',
    'single_quote',
    'spaces_after_semicolon',
    'spaces_before_semicolon',
    'spaces_cast',
    'standardize_not_equal',
    'ternary_spaces',
    'trailing_spaces',
    'trim_array_spaces',
    'unalign_double_arrow',
    'unalign_equals',
    'unary_operators_spaces',
    'unused_use',
    'visibility',
    'whitespacy_lines',
];

return Symfony\CS\Config\Config::create()
        ->level(Symfony\CS\FixerInterface::NONE_LEVEL)
        ->fixers($fixers)
        ->finder($finder);
