<?php

namespace Tymon\JWTAuth\Claims;

class JwtId extends Claim
{
    /**
     * The claim name
     *
     * @var string
     */
    protected $name = 'jti';
}
