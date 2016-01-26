<?php

$finder = Symfony\CS\Finder\DefaultFinder::create()
        ->in(__DIR__)
        ->exclude('config')
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
    'duplicate_semicolon',
    'extra_empty_lines',
    'header_comment',
    'phpdoc_scalar',
    'return',
    'short_array_syntax',
    'single_quote',
    'spaces_cast',
    'standardize_not_equal',
    'ternary_spaces',
    'trim_array_spaces',
    'unalign_double_arrow',
    'unalign_equals',
    'unneeded_control_parentheses',
    'unused_use',
    'whitespacy_lines',
];

return Symfony\CS\Config\Config::create()
        ->level(Symfony\CS\FixerInterface::PSR2_LEVEL)
        ->fixers($fixers)
        ->finder($finder);