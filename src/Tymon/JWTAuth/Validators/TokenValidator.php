<?php 

namespace Tymon\JWTAuth\Validators;

use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class TokenValidator
{
    /**
	 * Check the structure of the token
	 *
	 * @param $token
	 * @return bool
	 */
    public static function check($token)
    {
        self::validateStructure($token);
    }

    protected static function validateStructure($token)
    {
        if (count(explode('.', $token)) !== 3) {
            throw new TokenInvalidException('Wrong number of segments');
        }
    }
}
