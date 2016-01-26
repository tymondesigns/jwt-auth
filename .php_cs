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

return Symfony\CS\Config\Config::create()
        ->level(Symfony\CS\FixerInterface::PSR2_LEVEL)
        ->fixers(['short_array_syntax', '-psr0', 'header_comment'])
        ->finder($finder);