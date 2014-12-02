<?php

namespace Tymon\JWTAuth\Exceptions;

class TokenInvalidException extends JWTException
{
    /**
     * @var integer
     */
    protected $statusCode = 400;
}
