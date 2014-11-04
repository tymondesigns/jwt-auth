<?php

namespace Tymon\JWTAuth\Test\Providers\JWT;

use Mockery;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Providers\JWT\FirebaseAdapter;

class FirebaseAdapterTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->jwt = new FirebaseAdapter('secret', Request::create('/foo', 'GET'));
        $this->firebase = Mockery::mock('alias:Firebase');
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /** @test */
    public function it_should_return_the_token_when_passing_a_valid_subject_to_encode()
    {
        $token = $this->jwt->encode(1);

        $this->assertInstanceOf('Tymon\JWTAuth\Token', $token);
    }

    /** @test */
    public function it_should_return_the_payload_when_passing_a_valid_token_to_decode()
    {
        $token = $this->jwt->encode(1)->get();
        $payload = $this->jwt->decode($token);

        $this->assertInstanceOf('Tymon\JWTAuth\Payload', $payload);
    }

    /** @test */
    public function it_should_return_the_subject_via_helper_when_payload_is_already_set()
    {
        $token = $this->jwt->encode(1)->get();
        $payload = $this->jwt->decode($token);

        $this->assertEquals($this->jwt->getSubject(), 1);
    }

    /** @test */
    public function it_should_return_the_subject_via_helper_when_payload_is_not_set()
    {
        $token = $this->jwt->encode(1)->get();

        $this->assertEquals($this->jwt->getSubject($token), 1);
    }

    /** @test */
    public function it_should_throw_an_exception_when_no_token_or_payload_is_available()
    {
        $this->setExpectedException('Tymon\JWTAuth\Exceptions\JWTException');

        $this->assertEquals($this->jwt->getSubject(), 1);
    }

    /** @test */
    public function it_should_get_the_token()
    {
        $this->jwt->encode(1);

        $this->assertInstanceOf('Tymon\JWTAuth\Token', $this->jwt->getToken());
    }

    /** @test */
    public function it_should_get_the_payload()
    {
        $this->jwt->encode(1);

        $this->assertInstanceOf('Tymon\JWTAuth\Payload', $this->jwt->getPayload());
    }

}
