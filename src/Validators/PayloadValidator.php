<?php

namespace Tymon\JWTAuth\Validators;

use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class PayloadValidator extends AbstractValidator
{
    /**
     * @var array
     */
    protected static $requiredClaims = ['iss', 'iat', 'exp', 'sub', 'jti'];

    /**
     * Run the validation on the payload array
     *
     * @param  array  $value
     * @return void
     */
    public static function check($value)
    {
        self::validateStructure($value);
        self::validateExpiry($value);
    }

    /**
     * Ensure the payload contains the required claims
     *
     * @param  $payload
     * @return bool
     */
    protected static function validateStructure(array $payload)
    {
        if (count(array_diff(self::$requiredClaims, array_keys($payload))) !== 0) {
            throw new TokenInvalidException('JWT payload does not contain the required claims');
        }

        return true;
    }

    /**
     * Validate the issue and expiry date of the payload
     *
     * @param  $payload
     * @return bool
     */
    protected static function validateExpiry(array $payload)
    {
        if (! is_int($payload['exp'])) {
            throw new TokenInvalidException('Invalid Expiration (exp) provided');
        }

        if ($payload['iat'] > time() || $payload['exp'] < time()) {
            throw new TokenExpiredException('JWT has expired');
        }

        return true;
    }
}
