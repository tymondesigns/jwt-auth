<?php

namespace Tymon\JWTAuth\Claims;

use Tymon\JWTAuth\Claims\Issuer;
use Tymon\JWTAuth\Claims\IssuedAt;
use Tymon\JWTAuth\Claims\Expiration;
use Tymon\JWTAuth\Claims\NotBefore;
use Tymon\JWTAuth\Claims\Audience;
use Tymon\JWTAuth\Claims\Subject;
use Tymon\JWTAuth\Claims\JwtId;
use Tymon\JWTAuth\Claims\Custom;

class Factory
{

    /**
     * @var array
     */
    private static $classMap = [
        Audience::NAME    => Audience::class,
        Expiration::NAME  => Expiration::class,
        IssuedAt::NAME    => IssuedAt::class,
        Issuer::NAME      => Issuer::class,
        JwtId::NAME       => JwtId::class,
        NotBefore::NAME   => NotBefore::class,
        Subject::NAME     => Subject::class
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

        return with(new Custom($value))->setType($name);
    }
}