<?php

namespace Tymon\JWTAuth\Exceptions;

class PayloadException extends JWTException
{
    /**
     * @var integer
     */
    protected $statusCode = 500;
}
