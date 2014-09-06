<?php

namespace spec\Tymon\JWTAuth;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class JWTPayloadSpec extends ObjectBehavior
{

    function it_creates_the_object_when_passing_a_valid_payload()
    {
    	$payload = [
    		'iat' => time(),
    		'exp' => time() + (60 * 60), // plus 1 hour
    		'sub' => 1,
    		'jti' => '123123123',
    		'iss' => 'http://example.com',
    		'custom' => 'data'
    	];

    	$this->beConstructedWith($payload);
        $this->shouldHaveType('Tymon\JWTAuth\JWTPayload');

        $this->get()->shouldBe($payload);
    }

    function it_should_throw_an_exception_when_payload_does_not_contain_required_claims()
    {
    	$payload = ['iat' => 12312312, 'exp' => 13234234];

    	$this->shouldThrow('Tymon\JWTAuth\Exceptions\JWTPayloadException')->during('__construct', [$payload]);
    }

    // function it_should_throw_an_exception_when_payload_has_expired()
    // {
    	
    // }

}
