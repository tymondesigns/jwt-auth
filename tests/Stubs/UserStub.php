<?php

namespace Tymon\JWTAuth\Test\Stubs;

use Tymon\JWTAuth\JWTAuthSubject;
use Tymon\JWTAuth\Providers\JWT\JWTProvider;

class UserStub implements JWTAuthSubject
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
