<?php

namespace Tymon\JWTAuth\Test\Providers\JWT;

use Mockery;
use Tymon\JWTAuth\JWTManager;
use Tymon\JWTAuth\Payload;
use Tymon\JWTAuth\Token;

use Tymon\JWTAuth\Claims\Issuer;
use Tymon\JWTAuth\Claims\IssuedAt;
use Tymon\JWTAuth\Claims\Expiration;
use Tymon\JWTAuth\Claims\NotBefore;
use Tymon\JWTAuth\Claims\Audience;
use Tymon\JWTAuth\Claims\Subject;
use Tymon\JWTAuth\Claims\JwtId;
use Tymon\JWTAuth\Claims\Custom;

class JWTManagerTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->jwt = Mockery::mock('Tymon\JWTAuth\Providers\JWT\JWTInterface');
        $this->blacklist = Mockery::mock('Tymon\JWTAuth\Blacklist');
        $this->factory = Mockery::mock('Tymon\JWTAuth\PayloadFactory');
        $this->manager = new JWTManager($this->jwt, $this->blacklist, $this->factory);
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /** @test */
    public function it_should_encode_a_payload()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration(time() + 3600),
            new NotBefore(time()),
            new IssuedAt(time()),
            new JwtId('foo')
        ];
        $payload = new Payload($claims);

        $this->jwt->shouldReceive('encode')->with($payload->toArray())->andReturn('foo.bar.baz');

        $token = $this->manager->encode($payload);

        $this->assertEquals($token, 'foo.bar.baz');
    }

    /** @test */
    public function it_should_decode_a_token()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration(time() + 3600),
            new NotBefore(time()),
            new IssuedAt(time()),
            new JwtId('foo')
        ];
        $payload = new Payload($claims);
        $token = new Token('foo.bar.baz');
        $payloadArray = $payload->toArray();

        $this->jwt->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($payloadArray);
        $this->factory->shouldReceive('make')->with($payloadArray)->andReturn($payload);
        $this->blacklist->shouldReceive('has')->with($payload)->andReturn(false);

        $payload = $this->manager->decode($token);

        $this->assertInstanceOf('Tymon\JWTAuth\Payload', $payload);
    }

    /** @test */
    public function it_should_throw_exception_when_token_is_blacklisted()
    {
        $this->setExpectedException('Tymon\JWTAuth\Exceptions\TokenBlacklistedException');

        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration(time() + 3600),
            new NotBefore(time()),
            new IssuedAt(time()),
            new JwtId('foo')
        ];
        $payload = new Payload($claims);
        $token = new Token('foo.bar.baz');
        $payloadArray = $payload->toArray();

        $this->jwt->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($payloadArray);
        $this->factory->shouldReceive('make')->with($payloadArray)->andReturn($payload);
        $this->blacklist->shouldReceive('has')->with($payload)->andReturn(true);

        $payload = $this->manager->decode($token);
    }
}
