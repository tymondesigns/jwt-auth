<?php

namespace Tymon\JWTAuth\Facades;

use Illuminate\Support\Facades\Facade;

class JWTAuth extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'tymon.jwt.auth';
    }
}
