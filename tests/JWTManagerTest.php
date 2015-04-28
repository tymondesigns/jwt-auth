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

        $this->validator = Mockery::mock('Tymon\JWTAuth\Validators\PayloadValidator');
        $this->validator->shouldReceive('setRefreshFlow->check');
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
            new Expiration(123 + 3600),
            new NotBefore(123),
            new IssuedAt(123),
            new JwtId('foo')
        ];
        $payload = new Payload($claims, $this->validator);

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
            new Expiration(123 + 3600),
            new NotBefore(123),
            new IssuedAt(123),
            new JwtId('foo')
        ];
        $payload = new Payload($claims, $this->validator);
        $token = new Token('foo.bar.baz');

        $this->jwt->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($payload->toArray());
        $this->factory->shouldReceive('setRefreshFlow->make')->with($payload->toArray())->andReturn($payload);
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
            new Expiration(123 + 3600),
            new NotBefore(123),
            new IssuedAt(123),
            new JwtId('foo')
        ];
        $payload = new Payload($claims, $this->validator);
        $token = new Token('foo.bar.baz');

        $this->jwt->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($payload->toArray());
        $this->factory->shouldReceive('setRefreshFlow->make')->with($payload->toArray())->andReturn($payload);
        $this->blacklist->shouldReceive('has')->with($payload)->andReturn(true);

        $payload = $this->manager->decode($token);
    }

    /** @test */
    public function it_should_refresh_a_token()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration(123 - 3600),
            new NotBefore(123),
            new IssuedAt(123),
            new JwtId('foo')
        ];
        $payload = new Payload($claims, $this->validator, true);
        $token = new Token('foo.bar.baz');

        $this->jwt->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($payload->toArray());
        $this->jwt->shouldReceive('encode')->with($payload->toArray())->andReturn('baz.bar.foo');

        $this->factory->shouldReceive('setRefreshFlow')->andReturn($this->factory);
        $this->factory->shouldReceive('make')->andReturn($payload);

        $this->blacklist->shouldReceive('has')->with($payload)->andReturn(false);
        $this->blacklist->shouldReceive('add')->once()->with($payload);

        $token = $this->manager->refresh($token);

        $this->assertInstanceOf('Tymon\JWTAuth\Token', $token);
        $this->assertEquals('baz.bar.foo', $token);
    }

    /** @test */
    public function it_should_invalidate_a_token()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration(123 + 3600),
            new NotBefore(123),
            new IssuedAt(123),
            new JwtId('foo')
        ];
        $payload = new Payload($claims, $this->validator);
        $token = new Token('foo.bar.baz');

        $this->jwt->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($payload->toArray());
        $this->factory->shouldReceive('setRefreshFlow->make')->with($payload->toArray())->andReturn($payload);
        $this->blacklist->shouldReceive('has')->with($payload)->andReturn(false);

        $this->blacklist->shouldReceive('add')->with($payload)->andReturn(true);

        $this->manager->invalidate($token);
    }

    /** @test */
    public function it_should_throw_an_exception_when_enable_blacklist_is_set_to_false()
    {
        $this->setExpectedException('Tymon\JWTAuth\Exceptions\JWTException');

        $token = new Token('foo.bar.baz');

        $this->manager->setBlacklistEnabled(false)->invalidate($token);
    }

    /** @test */
    public function it_should_get_the_payload_factory()
    {
        $this->assertInstanceOf('Tymon\JWTAuth\PayloadFactory', $this->manager->getPayloadFactory());
    }

    /** @test */
    public function it_should_get_the_jwt_provider()
    {
        $this->assertInstanceOf('Tymon\JWTAuth\Providers\JWT\JWTInterface', $this->manager->getJWTProvider());
    }

    /** @test */
    public function it_should_get_the_blacklist()
    {
        $this->assertInstanceOf('Tymon\JWTAuth\Blacklist', $this->manager->getBlacklist());
    }
}
