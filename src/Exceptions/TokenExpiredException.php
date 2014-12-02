<?php

namespace Tymon\JWTAuth\Exceptions;

class TokenExpiredException extends JWTException
{
    /**
     * @var integer
     */
    protected $statusCode = 401;
}
