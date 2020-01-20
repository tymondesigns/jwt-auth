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
use Tymon\JWTAuth\JWT;
use Tymon\JWTAuth\Token;
use Tymon\JWTAuth\Builder;
use Tymon\JWTAuth\Manager;
use Tymon\JWTAuth\Payload;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Blacklist;
use Tymon\JWTAuth\Claims\Subject;
use Tymon\JWTAuth\Http\Parser\Parser;
use Tymon\JWTAuth\Test\Stubs\UserStub;
use Tymon\JWTAuth\Claims\HashedSubject;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Contracts\Providers\Auth;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class JWTTest extends AbstractTestCase
{
    /**
     * @var \Mockery\MockInterface|\Tymon\JWTAuth\Builder
     */
    protected $builder;

    /**
     * @var \Mockery\MockInterface|\Tymon\JWTAuth\Manager
     */
    protected $manager;

    /**
     * @var \Mockery\MockInterface|\Tymon\JWTAuth\Http\Parser\Parser
     */
    protected $parser;

    /**
     * @var \Tymon\JWTAuth\JWT
     */
    protected $jwt;

    public function setUp(): void
    {
        $this->builder = Mockery::spy(Builder::class);
        $this->manager = Mockery::spy(Manager::class);
        $this->parser = Mockery::spy(Parser::class);
        $this->jwt = new JWT($this->builder, $this->manager, $this->parser);
    }

    /** @test */
    public function it_should_return_a_token_when_passing_a_user()
    {
        $this->manager->shouldReceive('tokenForSubject')
            ->once()
            ->with($user = new UserStub, ['foo' => 'bar'])
            ->andReturn($token = new Token('foo.bar.baz'));

        $jwt = $this->jwt->claims(['foo' => 'bar'])->fromUser($user);

        $this->assertSame($jwt, $token);
        $this->assertSame((string) $jwt, 'foo.bar.baz');
    }

    /** @test */
    public function it_should_pass_hash_check_if_hash_matches()
    {
        $hash = sha1(UserStub::class);

        $payload = Mockery::mock(Payload::class)->shouldReceive('offsetExists')
            ->with(HashedSubject::NAME)
            ->andReturn(true)
            ->getMock();

        $payload->shouldReceive('get')
            ->with(HashedSubject::NAME)
            ->andReturn($hash);

        $this->builder->shouldReceive('hashSubjectModel')
            ->once()
            ->with(UserStub::class)
            ->andReturn($hash);

        $this->assertTrue(
            $this->jwt->setToken('foo.bar.baz')->checkSubjectModel(UserStub::class, $payload)
        );
    }

    /** @test */
    public function it_should_pass_provider_check_if_hash_matches_when_hashed_subject_is_null()
    {
        $payload = Mockery::mock(Payload::class)->shouldReceive('get')
            ->with(HashedSubject::NAME)
            ->andReturn(null)
            ->getMock();

        $this->assertTrue(
            $this->jwt->setToken('foo.bar.baz')
                ->checkSubjectModel('Tymon\JWTAuth\Test\Stubs\UserStub', $payload)
        );
    }

    /** @test */
    public function it_should_not_pass_provider_check_if_hash_not_match()
    {
        $payload = Mockery::mock(Payload::class)->shouldReceive('get')
            ->with(HashedSubject::NAME)
            ->andReturn(sha1('Tymon\JWTAuth\Test\Stubs\UserStub1'))
            ->getMock();

        $this->assertFalse(
            $this->jwt->setToken('foo.bar.baz')
                ->checkSubjectModel('Tymon\JWTAuth\Test\Stubs\UserStub', $payload)
        );
    }

    /** @test */
    public function it_should_refresh_a_token()
    {
        $this->manager->shouldReceive('refresh', 60)
            ->once()
            ->andReturn($token = new Token('baz.bar.foo'));

        $result = $this->jwt->setToken('foo.bar.baz')->refresh();

        $this->assertSame($result, $token);
        $this->assertSame((string) $result, 'baz.bar.foo');
    }

    /** @test */
    public function it_should_invalidate_a_token()
    {
        $token = new Token('foo.bar.baz');

        $this->manager->shouldReceive('invalidate')
            ->once()
            ->with($token)->andReturn(true);

        $this->jwt->setToken($token)->invalidate();
    }

    /** @test */
    public function it_should_retrieve_the_token_from_the_request()
    {
        $this->parser->shouldReceive('parseToken')->andReturn('foo.bar.baz');

        $this->assertInstanceOf(Token::class, $this->jwt->parseToken()->getToken());
        $this->assertEquals($this->jwt->getToken(), 'foo.bar.baz');
    }

    /** @test */
    public function it_should_get_the_authenticated_user()
    {
        $manager = $this->jwt->manager();
        $this->assertInstanceOf(Manager::class, $manager);
    }

    /** @test */
    public function it_should_return_false_if_the_token_is_invalid()
    {
        $this->parser->shouldReceive('parseToken')->andReturn('foo.bar.baz');
        $this->manager->shouldReceive('decode')
            ->once()
            ->andThrow(new TokenInvalidException);

        $this->assertFalse($this->jwt->parseToken()->check());
    }

    /** @test */
    public function it_should_return_true_if_the_token_is_valid()
    {
        $payload = Mockery::mock(Payload::class);

        $this->parser->shouldReceive('parseToken')->andReturn('foo.bar.baz');
        $this->manager->shouldReceive('decode')
            ->once()
            ->andReturn($payload);

        $this->assertTrue($this->jwt->parseToken()->check());
    }

    /** @test */
    public function it_should_throw_an_exception_when_token_not_present_in_request()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('The token could not be parsed from the request');

        $this->parser->shouldReceive('parseToken')->andReturn(false);

        $this->jwt->parseToken();
    }

    /** @test */
    public function it_should_return_false_when_no_token_is_set()
    {
        $this->parser->shouldReceive('parseToken')->andReturn(false);

        $this->assertNull($this->jwt->getToken());
    }

    /** @test */
    public function it_should_magically_call_the_manager()
    {
        $this->manager->shouldReceive('getBlacklist')->andReturn(Mockery::mock(Blacklist::class));

        $blacklist = $this->jwt->manager()->getBlacklist();

        $this->assertInstanceOf(Blacklist::class, $blacklist);
    }

    /** @test */
    public function it_should_set_the_request()
    {
        $request = Request::create('/foo', 'GET', ['token' => 'some.random.token']);

        $this->parser->shouldReceive('setRequest')
            ->once()
            ->with($request);
        $this->parser->shouldReceive('parseToken')->andReturn('some.random.token');

        $token = $this->jwt->setRequest($request)->getToken();

        $this->assertEquals('some.random.token', $token);
    }

    /** @test */
    public function it_should_unset_the_token()
    {
        $this->parser->shouldReceive('parseToken')->andThrow(new JWTException);
        $token = new Token('foo.bar.baz');
        $this->jwt->setToken($token);

        $this->assertSame($this->jwt->getToken(), $token);
        $this->jwt->unsetToken();
        $this->assertNull($this->jwt->getToken());
    }

    /** @test */
    public function it_should_register_a_custom_claim_validator()
    {
        $this->builder->shouldReceive('setCustomValidator')
            ->with('foo', Mockery::type('callable'))
            ->once();

        $this->jwt->registerCustomValidator('foo', fn ($value) => $value !== 'bar');
    }

    /** @test */
    public function it_should_get_the_manager_instance()
    {
        $this->assertInstanceOf(Manager::class, $this->jwt->manager());
    }

    /** @test */
    public function it_should_get_the_parser_instance()
    {
        $this->assertInstanceOf(Parser::class, $this->jwt->parser());
    }

    /** @test */
    public function it_should_get_a_claim_value()
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('get')
            ->once()
            ->with(Subject::NAME)
            ->andReturn(1);

        $this->manager->shouldReceive('decode')
            ->once()
            ->andReturn($payload);

        $this->assertSame($this->jwt->setToken('foo.bar.baz')->getClaim(Subject::NAME), 1);
    }
}
