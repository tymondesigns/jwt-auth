<?php

namespace Tymon\JWTAuth\Test\Providers\JWT;

use Mockery;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Providers\JWT\NamshiAdapter;

class NamshiAdapterTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
    	$this->jws = Mockery::mock('Namshi\JOSE\JWS');
        $this->provider = new NamshiAdapter('secret', 'HS256', $this->jws);
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /** @test */
    public function it_should_return_the_token_when_passing_a_valid_subject_to_encode()
    {
    	$payload = ['sub' => 1, 'exp' => time(), 'iat' => time(), 'iss' => '/foo'];

        // $this->jws->shouldReceive('setPayload')->once()->with($payload)->andReturn(Mockery::self());
        // $this->jws->shouldReceive('sign')->once()->with('secret')->andReturn(Mockery::self());
        // $this->jws->shouldReceive('getTokenString')->once()->andReturn('foo.bar.baz');

        $token = $this->provider->encode($payload);

        // $this->assertEquals('foo.bar.baz', $token);
    }

    // /** @test */
    // public function it_should_return_the_payload_when_passing_a_valid_token_to_decode()
    // {
    //     $this->jws->shouldReceive('load')->once()->with('foo.bar.baz')->andReturn(true);

    //     $payload = $this->provider->decode('foo.bar.baz');

    // }

    // /** @test */
    // public function it_should_return_the_subject_via_helper_when_payload_is_already_set()
    // {
    //     $this->blacklist->shouldReceive('has')->once()->andReturn(false);

    //     $token = $this->provider->encode(1)->get();
    //     $payload = $this->provider->decode($token);

    //     $this->assertEquals($this->provider->getSubject(), 1);
    // }

    // /** @test */
    // public function it_should_return_the_subject_via_helper_when_payload_is_not_set()
    // {
    //     $this->blacklist->shouldReceive('has')->once()->andReturn(false);

    //     $token = $this->provider->encode(1)->get();

    //     $this->assertEquals($this->provider->getSubject($token), 1);
    // }

    // /** @test */
    // public function it_should_throw_an_exception_when_no_token_or_payload_is_available()
    // {
    //     $this->setExpectedException('Tymon\JWTAuth\Exceptions\JWTException');

    //     $this->assertEquals($this->provider->getSubject(), 1);
    // }

    // /** @test */
    // public function it_should_get_the_token()
    // {
    //     $this->provider->encode(1);

    //     $this->assertInstanceOf('Tymon\JWTAuth\Token', $this->provider->getToken());
    // }

    // /** @test */
    // public function it_should_get_the_payload()
    // {
    //     $this->blacklist->shouldReceive('has')->once()->andReturn(false);

    //     $token = $this->provider->encode(1);
    //     $this->provider->decode($token);

    //     $this->assertInstanceOf('Tymon\JWTAuth\Payload', $this->provider->getPayload());
    // }

    // /** @test */
    // public function it_should_set_the_ttl()
    // {
    //     $this->provider->setTTL(1440);

    //     $this->assertEquals(1440, $this->provider->getTTL());
    // }

    // /** @test */
    // public function it_should_set_the_algo()
    // {
    //     $this->provider->setAlgo('HS512');

    //     $this->assertEquals('HS512', $this->provider->getAlgo());
    // }

}
