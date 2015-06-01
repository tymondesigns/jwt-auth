<?php

$finder = Symfony\CS\Finder\DefaultFinder::create()
        ->in(__DIR__)
        ->ignoreDotFiles(true);

return Symfony\CS\Config\Config::create()
        ->level(Symfony\CS\FixerInterface::PSR2_LEVEL)
        ->fixers(['short_array_syntax', '-psr0'])
        ->finder($finder);