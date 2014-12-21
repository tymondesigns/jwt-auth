<?php

namespace Tymon\JWTAuth\Exceptions;

class InvalidClaimException extends JWTException
{
    /**
     * @var integer
     */
    protected $statusCode = 400;
}
