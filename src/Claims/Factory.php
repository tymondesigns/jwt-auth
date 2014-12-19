<?php

namespace Tymon\JWTAuth\Claims;

use Tymon\JWTAuth\Claims\Custom;

class Factory
{

    /**
     * @var array
     */
    private static $classMap = [
        'aud' => 'Tymon\JWTAuth\Claims\Audience',
        'exp' => 'Tymon\JWTAuth\Claims\Expiration',
        'iat' => 'Tymon\JWTAuth\Claims\IssuedAt',
        'iss' => 'Tymon\JWTAuth\Claims\Issuer',
        'jti' => 'Tymon\JWTAuth\Claims\JwtId',
        'nbf' => 'Tymon\JWTAuth\Claims\NotBefore',
        'sub' => 'Tymon\JWTAuth\Claims\Subject'
    ];

    /**
     * Get the instance of the claim when passing the type and value
     *
     * @param  string  $name
     * @param  mixed   $value
     * @return \Tymon\JWTAuth\Claims\Claim
     */
    public function get($name, $value)
    {
        if (array_key_exists($name, self::$classMap)) {
            return new self::$classMap[$name]($value);
        }

        return new Custom($value, $name);
    }

    public function has($name)
    {
        return array_key_exists($name, self::$classMap);
    }
}