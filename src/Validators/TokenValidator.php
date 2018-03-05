<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Validators;

use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class TokenValidator extends Validator
{
    /**
     * Check the structure of the token.
     *
     * @param  mixed  $value
     */
    public function check($value): string
    {
        return $this->validateStructure($value);
    }

    /**
     * Validate the token structure
     *
     * @throws \Tymon\JWTAuth\Exceptions\TokenInvalidException
     */
    protected function validateStructure(string $token): string
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new TokenInvalidException('Wrong number of segments');
        }

        $parts = array_filter(array_map('trim', $parts));

        if (count($parts) !== 3 || implode('.', $parts) !== $token) {
            throw new TokenInvalidException('Malformed token');
        }

        return $token;
    }
}
