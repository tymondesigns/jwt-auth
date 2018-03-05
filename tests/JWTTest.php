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
use Tymon\JWTAuth\Factory;
use Tymon\JWTAuth\Manager;
use Tymon\JWTAuth\Payload;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Blacklist;
use Tymon\JWTAuth\Http\Parser\Parser;
use Tymon\JWTAuth\Test\Stubs\UserStub;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Contracts\Providers\Auth;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class JWTTest extends AbstractTestCase
{
    /**
     * @var \Mockery\MockInterface|\Tymon\JWTAuth\Manager
     */
    protected $manager;

    /**
     * @var \Mockery\MockInterface|\Tymon\JWTAuth\Contracts\Providers\Auth
     */
    protected $auth;

    /**
     * @var \Mockery\MockInterface|\Tymon\JWTAuth\Http\Parser\Parser
     */
    protected $parser;

    /**
     * @var \Tymon\JWTAuth\JWT
     */
    protected $jwt;

    public function setUp()
    {
        $this->manager = Mockery::mock(Manager::class);
        $this->parser = Mockery::mock(Parser::class);
        $this->jwtAuth = new JWT($this->manager, $this->parser);
    }

    /** @test */
    public function it_should_return_a_token_when_passing_a_user()
    {
        $payloadFactory = Mockery::mock(Factory::class);
        $payloadFactory->shouldReceive('make')->andReturn(Mockery::mock(Payload::class));

        $this->manager
             ->shouldReceive('getPayloadFactory->customClaims')
             ->once()
             ->with(['sub' => 1, 'prv' => sha1('Tymon\JWTAuth\Test\Stubs\UserStub'), 'foo' => 'bar', 'role' => 'admin'])
             ->andReturn($payloadFactory);

        $this->manager->shouldReceive('encode->get')->once()->andReturn('foo.bar.baz');

        $token = $this->jwtAuth->fromUser(new UserStub);

        $this->assertSame($token, 'foo.bar.baz');
    }

    /** @test */
    public function it_should_pass_provider_check_if_hash_matches()
    {
        $payload = Mockery::mock(Payload::class)->shouldReceive('get')
                ->with('prv')
                ->andReturn(sha1('Tymon\JWTAuth\Test\Stubs\UserStub'))
                ->getMock();

        $this->manager->shouldReceive('decode')->once()->andReturn($payload);

        $this->assertTrue($this->jwtAuth->setToken('foo.bar.baz')->checkSubjectModel('Tymon\JWTAuth\Test\Stubs\UserStub'));
    }

    /** @test */
    public function it_should_pass_provider_check_if_hash_matches_when_provider_is_null()
    {
        $payload = Mockery::mock(Payload::class)->shouldReceive('get')
                ->with('prv')
                ->andReturnNull()
                ->getMock();

        $this->manager->shouldReceive('decode')->once()->andReturn($payload);

        $this->assertTrue($this->jwtAuth->setToken('foo.bar.baz')->checkSubjectModel('Tymon\JWTAuth\Test\Stubs\UserStub'));
    }

    /** @test */
    public function it_should_not_pass_provider_check_if_hash_not_match()
    {
        $payload = Mockery::mock(Payload::class)->shouldReceive('get')
                ->with('prv')
                ->andReturn(sha1('Tymon\JWTAuth\Test\Stubs\UserStub1'))
                ->getMock();

        $this->manager->shouldReceive('decode')->once()->andReturn($payload);

        $this->assertFalse($this->jwtAuth->setToken('foo.bar.baz')->checkSubjectModel('Tymon\JWTAuth\Test\Stubs\UserStub'));
    }

    /** @test */
    public function it_should_refresh_a_token()
    {
        $newToken = Mockery::mock(Token::class);
        $newToken->shouldReceive('get')->once()->andReturn('baz.bar.foo');

        $this->manager->shouldReceive('customClaims->refresh')->once()->andReturn($newToken);

        $result = $this->jwtAuth->setToken('foo.bar.baz')->refresh();

        $this->assertSame($result, 'baz.bar.foo');
    }

    /** @test */
    public function it_should_invalidate_a_token()
    {
        $token = new Token('foo.bar.baz');

        $this->manager->shouldReceive('invalidate')->once()->with($token, false)->andReturn(true);

        $this->jwtAuth->setToken($token)->invalidate();
    }

    /** @test */
    public function it_should_force_invalidate_a_token_forever()
    {
        $token = new Token('foo.bar.baz');

        $this->manager->shouldReceive('invalidate')->once()->with($token, true)->andReturn(true);

        $this->jwtAuth->setToken($token)->invalidate(true);
    }

    /** @test */
    public function it_should_retrieve_the_token_from_the_request()
    {
        $this->parser->shouldReceive('parseToken')->andReturn('foo.bar.baz');

        $this->assertInstanceOf(Token::class, $this->jwtAuth->parseToken()->getToken());
        $this->assertEquals($this->jwtAuth->getToken(), 'foo.bar.baz');
    }

    /** @test */
    public function it_should_get_the_authenticated_user()
    {
        $manager = $this->jwtAuth->manager();
        $this->assertInstanceOf(Manager::class, $manager);
    }

    /** @test */
    public function it_should_return_false_if_the_token_is_invalid()
    {
        $this->parser->shouldReceive('parseToken')->andReturn('foo.bar.baz');
        $this->manager->shouldReceive('decode')->once()->andThrow(new TokenInvalidException);

        $this->assertFalse($this->jwtAuth->parseToken()->check());
    }

    /** @test */
    public function it_should_return_true_if_the_token_is_valid()
    {
        $payload = Mockery::mock(Payload::class);

        $this->parser->shouldReceive('parseToken')->andReturn('foo.bar.baz');
        $this->manager->shouldReceive('decode')->once()->andReturn($payload);

        $this->assertTrue($this->jwtAuth->parseToken()->check());
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\JWTException
     * @expectedExceptionMessage The token could not be parsed from the request
     */
    public function it_should_throw_an_exception_when_token_not_present_in_request()
    {
        $this->parser->shouldReceive('parseToken')->andReturn(false);

        $this->jwtAuth->parseToken();
    }

    /** @test */
    public function it_should_return_false_when_no_token_is_set()
    {
        $this->parser->shouldReceive('parseToken')->andReturn(false);

        $this->assertNull($this->jwtAuth->getToken());
    }

    /** @test */
    public function it_should_magically_call_the_manager()
    {
        $this->manager->shouldReceive('getBlacklist')->andReturn(Mockery::mock(Blacklist::class));

        $blacklist = $this->jwtAuth->manager()->getBlacklist();

        $this->assertInstanceOf(Blacklist::class, $blacklist);
    }

    /** @test */
    public function it_should_set_the_request()
    {
        $request = Request::create('/foo', 'GET', ['token' => 'some.random.token']);

        $this->parser->shouldReceive('setRequest')->once()->with($request);
        $this->parser->shouldReceive('parseToken')->andReturn('some.random.token');

        $token = $this->jwtAuth->setRequest($request)->getToken();

        $this->assertEquals('some.random.token', $token);
    }

    /** @test */
    public function it_should_unset_the_token()
    {
        $this->parser->shouldReceive('parseToken')->andThrow(new JWTException);
        $token = new Token('foo.bar.baz');
        $this->jwtAuth->setToken($token);

        $this->assertSame($this->jwtAuth->getToken(), $token);
        $this->jwtAuth->unsetToken();
        $this->assertNull($this->jwtAuth->getToken());
    }

    /** @test */
    public function it_should_get_the_manager_instance()
    {
        $manager = $this->jwtAuth->manager();
        $this->assertInstanceOf(Manager::class, $manager);
    }

    /** @test */
    public function it_should_get_the_parser_instance()
    {
        $parser = $this->jwtAuth->parser();
        $this->assertInstanceOf(Parser::class, $parser);
    }

    /** @test */
    public function it_should_get_a_claim_value()
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('get')->once()->with('sub')->andReturn(1);

        $this->manager->shouldReceive('decode')->once()->andReturn($payload);

        $this->assertSame($this->jwtAuth->setToken('foo.bar.baz')->getClaim('sub'), 1);
    }
}
