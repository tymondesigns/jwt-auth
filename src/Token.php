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

namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Validators\TokenValidator;

class Token
{
    /**
     * @var string
     */
    private $value;

    /**
     * Create a new JSON Web Token.
     */
    public function __construct(string $value)
    {
        $this->value = TokenValidator::check($value);
    }

    /**
     * Get the token.
     */
    public function get(): string
    {
        return $this->value;
    }

    /**
     * Checks if a token matches this one.
     */
    public function matches($token): bool
    {
        return (string) $this->get() === (string) $token;
    }

    /**
     * Get the token when casting to string.
     */
    public function __toString(): string
    {
        return $this->get();
    }
}
