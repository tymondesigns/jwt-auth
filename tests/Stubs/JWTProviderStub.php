<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test\Stubs;

use Tymon\JWTAuth\Providers\JWT\Provider;

class JWTProviderStub extends Provider
{
    /**
     * {@inheritdoc}
     */
    protected function isAsymmetric(): bool
    {
        return false;
    }

    /**
     * Create a JSON Web Token.
     */
    public function encode(array $payload): string
    {
        return 'foo.bar.baz';
    }

    /**
     * Decode a JSON Web Token.
     */
    public function decode(string $token): array
    {
        return ['foo' => 'bar'];
    }
}
