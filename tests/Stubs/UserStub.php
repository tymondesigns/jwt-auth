<?php

namespace Tymon\JWTAuth\Test\Stubs;

use Tymon\JWTAuth\JWTAuthSubject;
use Tymon\JWTAuth\Providers\JWT\JWTProvider;

class UserStub implements JWTAuthSubject
{
    public function getIdentifier()
    {
        return 1;
    }

    public function getCustomClaims()
    {
        return [
            'foo' => 'bar',
            'role' => 'admin'
        ];
    }
}
