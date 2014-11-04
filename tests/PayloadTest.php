<?php

namespace Tymon\JWTAuth\Test\Providers\JWT;

use Tymon\JWTAuth\Payload;

class PayloadTest extends \PHPUnit_Framework_TestCase
{
	public function setUp()
	{
		$this->payload = new Payload([
        	'iss' => 'http://example.com',
        	'iat' => time(),
        	'exp' => time() + 3600,
        	'sub' => 1
        ]);
	}

	/** @test */
    public function it_throws_an_exception_when_trying_to_add_to_the_payload()
    {
        $this->setExpectedException('Tymon\JWTAuth\Exceptions\PayloadException');

        $this->payload['foo'] = 'bar';
    }

    /** @test */
    public function it_throws_an_exception_when_trying_to_remove_a_key_from_the_payload()
    {
        $this->setExpectedException('Tymon\JWTAuth\Exceptions\PayloadException');

        unset($this->payload['foo']);
    }

    /** @test */
    public function it_should_cast_the_payload_to_a_string_as_json()
    {
    	$this->assertEquals((string) $this->payload, json_encode($this->payload->get()));
    }

}