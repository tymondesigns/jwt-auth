<?php

namespace spec\Tymon\JWTAuth;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Tymon\JWTAuth\Providers\FirebaseProvider;
use Mockery;

class JWTAuthSpec extends ObjectBehavior
{
    function it_is_initializable(FirebaseProvider $provider)
    {
    	$auth = Mockery::mock('Illuminate\Auth\AuthManager');
    	$this->beConstructedWith($provider, $auth);

        $this->shouldHaveType('Tymon\JWTAuth\JWTAuth');
    }
}
