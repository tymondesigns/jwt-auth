<?php

namespace Tymon\JWTAuth\Test\Providers\JWT;

use Mockery;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Providers\JWT\NamshiAdapter;

class FirebaseAdapterTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
    	$this->namshi = Mockery::mock('Namshi\JOSE\JWS');
        $this->jwt = new NamshiAdapter('secret', $this->namshi);
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /** @test */
    public function it_should_return_the_token_when_passing_a_valid_subject_to_encode()
    {
    	$payload = ['sub' => 1, 'exp' => time(), 'iat' => time(), 'iss' => '/foo'];

        $this->namshi->shouldReceive('setPayload')->once()->with($payload)->andReturn($this->namshi);
        $this->namshi->shouldReceive('sign')->once()->with('secret')->andReturn($this->namshi);
        $this->namshi->shouldReceive('getTokenString')->once()->andReturn('foo.bar.baz');

        $token = $this->jwt->encode($payload);

        $this->assertEquals('foo.bar.baz', $token);
    }

    // /** @test */
    // public function it_should_return_the_payload_when_passing_a_valid_token_to_decode()
    // {
    //     $this->namshi->shouldReceive('load')->once()->with('foo.bar.baz')->andReturn(true);

    //     $payload = $this->jwt->decode('foo.bar.baz');

    // }

    // /** @test */
    // public function it_should_return_the_subject_via_helper_when_payload_is_already_set()
    // {
    //     $this->blacklist->shouldReceive('has')->once()->andReturn(false);

    //     $token = $this->jwt->encode(1)->get();
    //     $payload = $this->jwt->decode($token);

    //     $this->assertEquals($this->jwt->getSubject(), 1);
    // }

    // /** @test */
    // public function it_should_return_the_subject_via_helper_when_payload_is_not_set()
    // {
    //     $this->blacklist->shouldReceive('has')->once()->andReturn(false);

    //     $token = $this->jwt->encode(1)->get();

    //     $this->assertEquals($this->jwt->getSubject($token), 1);
    // }

    // /** @test */
    // public function it_should_throw_an_exception_when_no_token_or_payload_is_available()
    // {
    //     $this->setExpectedException('Tymon\JWTAuth\Exceptions\JWTException');

    //     $this->assertEquals($this->jwt->getSubject(), 1);
    // }

    // /** @test */
    // public function it_should_get_the_token()
    // {
    //     $this->jwt->encode(1);

    //     $this->assertInstanceOf('Tymon\JWTAuth\Token', $this->jwt->getToken());
    // }

    // /** @test */
    // public function it_should_get_the_payload()
    // {
    //     $this->blacklist->shouldReceive('has')->once()->andReturn(false);

    //     $token = $this->jwt->encode(1);
    //     $this->jwt->decode($token);

    //     $this->assertInstanceOf('Tymon\JWTAuth\Payload', $this->jwt->getPayload());
    // }

    // /** @test */
    // public function it_should_set_the_ttl()
    // {
    //     $this->jwt->setTTL(1440);

    //     $this->assertEquals(1440, $this->jwt->getTTL());
    // }

    // /** @test */
    // public function it_should_set_the_algo()
    // {
    //     $this->jwt->setAlgo('HS512');

    //     $this->assertEquals('HS512', $this->jwt->getAlgo());
    // }

}
