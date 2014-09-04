<?php

namespace spec\Tymon\JWTAuth;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class JWTAuthSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('Tymon\JWTAuth\JWTAuth');
    }

    function it_should_create_a_jwt_based_on_a_subject()
    {
    	
    }
}
