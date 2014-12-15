<?php

namespace Tymon\JWTAuth\Test\Providers\JWT;

use Mockery;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Providers\JWT\FirebaseAdapter;

class FirebaseAdapterTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->blacklist = Mockery::mock('Tymon\JWTAuth\Blacklist');
        $this->jwt = new FirebaseAdapter('secret', $this->blacklist, Request::create('/foo', 'GET'));
        $this->firebase = Mockery::mock('overload:Firebase');
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /** @test */
    public function it_should_return_the_token_when_passing_a_valid_subject_to_encode()
    {
        $this->firebase->shouldReceive('encode')->once()->with(1)->andReturn('foo.bar.baz');

        $token = $this->jwt->encode(1);

        $this->assertInstanceOf('Tymon\JWTAuth\Token', $token);
    }

    /** @test */
    public function it_should_return_the_payload_when_passing_a_valid_token_to_decode()
    {
        $this->blacklist->shouldReceive('has')->once()->andReturn(false);

        $token = $this->jwt->encode(1)->get();
        $payload = $this->jwt->decode($token);

        $this->assertInstanceOf('Tymon\JWTAuth\Payload', $payload);
    }

    /** @test */
    public function it_should_return_the_subject_via_helper_when_payload_is_already_set()
    {
        $this->blacklist->shouldReceive('has')->once()->andReturn(false);

        $token = $this->jwt->encode(1)->get();
        $payload = $this->jwt->decode($token);

        $this->assertEquals($this->jwt->getSubject(), 1);
    }

    /** @test */
    public function it_should_return_the_subject_via_helper_when_payload_is_not_set()
    {
        $this->blacklist->shouldReceive('has')->once()->andReturn(false);

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
        $this->blacklist->shouldReceive('has')->once()->andReturn(false);

        $token = $this->jwt->encode(1);
        $this->jwt->decode($token);

        $this->assertInstanceOf('Tymon\JWTAuth\Payload', $this->jwt->getPayload());
    }

    /** @test */
    public function it_should_set_the_ttl()
    {
        $this->jwt->setTTL(1440);

        $this->assertEquals(1440, $this->jwt->getTTL());
    }

    /** @test */
    public function it_should_set_the_algo()
    {
        $this->jwt->setAlgo('HS512');

        $this->assertEquals('HS512', $this->jwt->getAlgo());
    }

}
