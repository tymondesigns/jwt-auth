<?php

namespace Tymon\JWTAuth\Exceptions;

class TokenBlacklistedException extends TokenInvalidException
{
    /**
     * @var integer
     */
    protected $statusCode = 401;
}
