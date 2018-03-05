<?php

declare(strict_types=1);

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Contracts\Providers;

interface JWT
{
    /**
     * Create a JSON Web Token.
     */
    public function encode(array $payload): string;

    /**
     * Decode a JSON Web Token.
     */
    public function decode(string $token): array;
}
