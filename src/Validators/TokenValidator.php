<?php

namespace Tymon\JWTAuth\Validators;

use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class TokenValidator
{
    /**
     * Check the structure of the token
     *
     * @param string $token
     * @return boolean|null
     */
    public static function check($token)
    {
        self::validateStructure($token);
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
