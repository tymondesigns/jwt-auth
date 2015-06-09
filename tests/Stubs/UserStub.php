<?php

namespace Tymon\JWTAuth\Test\Stubs;

use Tymon\JWTAuth\Contracts\JWTSubject;
use Tymon\JWTAuth\Providers\JWT\JWTProvider;

class UserStub implements JWTSubject
{
    public function getJWTIdentifier()
    {
        return 1;
    }

    public function getJWTCustomClaims()
    {
        return [
            'foo' => 'bar',
            'role' => 'admin'
        ];
    }
}
