<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test;

use Mockery;
use Tymon\JWTAuth\Token;
use Tymon\JWTAuth\Builder;
use Tymon\JWTAuth\Factory;
use Tymon\JWTAuth\Manager;
use Tymon\JWTAuth\Options;
use Tymon\JWTAuth\Payload;
use Tymon\JWTAuth\Blacklist;
use Tymon\JWTAuth\Claims\JwtId;
use Tymon\JWTAuth\Claims\Issuer;
use Tymon\JWTAuth\Claims\Subject;
use Tymon\JWTAuth\Claims\IssuedAt;
use Tymon\JWTAuth\Claims\NotBefore;
use Tymon\JWTAuth\Claims\Expiration;
use Tymon\JWTAuth\Contracts\Providers\JWT;

class ManagerTest extends AbstractTestCase
{
    /**
     * @var \Mockery\MockInterface|\Tymon\JWTAuth\Contracts\Providers\JWT
     */
    protected $jwt;

    /**
     * @var \Mockery\MockInterface|\Tymon\JWTAuth\Blacklist
     */
    protected $blacklist;

    /**
     * @var \Mockery\MockInterface|\Tymon\JWTAuth\Factory
     */
    protected $factory;

    /**
     * @var \Mockery\MockInterface|\Tymon\JWTAuth\Builder
     */
    protected $builder;

    /**
     * @var \Tymon\JWTAuth\Manager
     */
    protected $manager;

    public function setUp()
    {
        parent::setUp();

        $this->jwt = Mockery::mock(JWT::class);
        $this->blacklist = Mockery::mock(Blacklist::class);
        $this->builder = Mockery::mock(Builder::class);
        $this->manager = new Manager($this->jwt, $this->blacklist, $this->builder);
    }

    /** @test */
    public function it_should_encode_a_payload()
    {
        $payload = Factory::make([
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ]);

        $this->jwt->shouldReceive('token')
            ->with($payload)
            ->andReturn(new Token('foo.bar.baz'));

        $token = $this->manager->encode($payload);

        $this->assertEquals($token, 'foo.bar.baz');
    }

    /** @test */
    public function it_should_decode_a_token()
    {
        $payload = Factory::make([
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ]);

        $token = new Token('foo.bar.baz');
        $options = new Options();

        $this->jwt->shouldReceive('payload')
            ->once()
            ->with($token, $options)
            ->andReturn($payload);

        $this->blacklist->shouldReceive('has')
            ->with($payload)
            ->andReturn(false);

        $this->builder->shouldReceive('getOptions')
            ->once()
            ->andReturn($options);

        $payload = $this->manager->decode($token);

        $this->assertInstanceOf(Payload::class, $payload);
        $this->assertSame($payload->count(), 6);
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\TokenBlacklistedException
     * @expectedExceptionMessage The token has been blacklisted
     */
    public function it_should_throw_exception_when_token_is_blacklisted()
    {
        $payload = Factory::make([
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ]);

        $token = new Token('foo.bar.baz');
        $options = new Options();

        $this->jwt->shouldReceive('payload')
            ->once()
            ->with($token, $options)
            ->andReturn($payload);

        $this->blacklist->shouldReceive('has')
            ->with($payload)
            ->andReturn(true);

        $this->builder->shouldReceive('getOptions')
            ->once()
            ->andReturn($options);

        $this->manager->decode($token);
    }

    /** @test */
    public function it_should_refresh_a_token()
    {
        $payload = Factory::make([
            new Subject(1),
            new Issuer('example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ]);

        $token = new Token('foo.bar.baz');
        $options = new Options();

        $this->jwt->shouldReceive('payload')
            ->twice()
            ->with($token, $options)
            ->andReturn($payload);

        $this->jwt->shouldReceive('token')
            ->once()
            ->with(Mockery::type(Payload::class))
            ->andReturn(new Token('baz.bar.foo'));

        $this->blacklist->shouldReceive('has')
            ->with($payload)
            ->andReturn(false);
        $this->blacklist->shouldReceive('add')
            ->once()
            ->with($payload);

        $this->builder->shouldReceive('getOptions')
            ->twice()
            ->andReturn($options);

        $this->builder->shouldReceive('getTTL')
            ->once();

        $this->builder->shouldReceive('make')
            ->once()
            ->andReturn($payload);

        $token = $this->manager->refresh($token);

        $this->assertInstanceOf(Token::class, $token);
        $this->assertEquals('baz.bar.foo', $token);
    }

    /** @test */
    public function it_should_invalidate_a_token()
    {
        $payload = Factory::make([
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ]);

        $token = new Token('foo.bar.baz');
        $options = new Options();

        $this->jwt->shouldReceive('payload')
            ->once()
            ->with($token, $options)
            ->andReturn($payload);

        $this->blacklist->shouldReceive('has')
            ->with($payload)
            ->andReturn(false);

        $this->blacklist->shouldReceive('add')
            ->with($payload)
            ->andReturn(true);

        $this->builder->shouldReceive('getOptions')
            ->once()
            ->andReturn($options);

        $this->manager->invalidate($token);
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\JWTException
     * @expectedExceptionMessage You must have the blacklist enabled to invalidate a token.
     */
    public function it_should_throw_an_exception_when_enable_blacklist_is_set_to_false()
    {
        $token = new Token('foo.bar.baz');

        $this->manager->setBlacklistEnabled(false)->invalidate($token);
    }

    /** @test */
    public function it_should_get_the_jwt_provider()
    {
        $this->assertInstanceOf(JWT::class, $this->manager->getJWTProvider());
    }

    /** @test */
    public function it_should_get_the_blacklist()
    {
        $this->assertInstanceOf(Blacklist::class, $this->manager->getBlacklist());
    }

    /** @test */
    public function it_should_get_the_builder()
    {
        $this->assertInstanceOf(Builder::class, $this->manager->builder());
    }
}
