<?php

namespace Tymon\JWTAuth\Validators;

use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class TokenValidator extends AbstractValidator
{
    /**
     * Check the structure of the token
     *
     * @param string $value
     * @return boolean|null
     */
    public static function check($value)
    {
        self::validateStructure($value);
    }

    /**
     * @param string $token
     */
    protected static function validateStructure($token)
    {
        if (count(explode('.', $token)) !== 3) {
            throw new TokenInvalidException('Wrong number of segments');
        }
    }
}
