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
use Tymon\JWTAuth\Payload;
use Tymon\JWTAuth\JWTGuard;
use Illuminate\Http\Request;
use Illuminate\Auth\EloquentUserProvider;
use Tymon\JWTAuth\Test\Stubs\LaravelUserStub;

class JWTGuardTest extends AbstractTestCase
{
    /**
     * @var \Tymon\JWTAuth\JWT|\Mockery\MockInterface
     */
    protected $jwt;

    /**
     * @var \Illuminate\Contracts\Auth\UserProvider|\Mockery\MockInterface
     */
    protected $provider;

    /**
     * @var \Tymon\JWTAuth\JWTGuard|\Mockery\MockInterface
     */
    protected $guard;

    public function setUp()
    {
        parent::setUp();

        $this->jwt = Mockery::mock(JWT::class);
        $this->provider = Mockery::mock(EloquentUserProvider::class);
        $this->guard = new JWTGuard($this->jwt, $this->provider, Request::create('/foo', 'GET'));
        $this->guard->useResponsable(false);
    }

    /**
     * @test
     */
    public function it_should_get_the_request()
    {
        $this->assertInstanceOf(Request::class, $this->guard->getRequest());
    }

    /**
     * @test
     */
    public function it_should_get_the_authenticated_user_if_a_valid_token_is_provided()
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('offsetGet')->once()->with('sub')->andReturn(1);

        $this->jwt->shouldReceive('setRequest')->andReturn($this->jwt);
        $this->jwt->shouldReceive('getToken')->once()->andReturn(new Token('foo.bar.baz'));
        $this->jwt->shouldReceive('check')->once()->with(true)->andReturn($payload);
        $this->jwt->shouldReceive('checkSubjectModel')
                  ->once()
                  ->with(LaravelUserStub::class, $payload)
                  ->andReturn(true);

        $this->provider->shouldReceive('getModel')
                       ->once()
                       ->andReturn(LaravelUserStub::class);
        $this->provider->shouldReceive('retrieveById')
                       ->once()
                       ->with(1)
                       ->andReturn((object) ['id' => 1]);

        $this->assertSame(1, $this->guard->user()->id);

        // check that the user is stored on the object next time round
        $this->assertSame(1, $this->guard->user()->id);
        $this->assertTrue($this->guard->check());

        // also make sure userOrFail does not fail
        $this->assertSame(1, $this->guard->userOrFail()->id);
    }

    /**
     * @test
     */
    public function it_should_get_the_authenticated_user_if_a_valid_token_is_provided_and_not_throw_an_exception()
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('offsetGet')->once()->with('sub')->andReturn(1);

        $this->jwt->shouldReceive('setRequest')->andReturn($this->jwt);
        $this->jwt->shouldReceive('getToken')->once()->andReturn(new Token('foo.bar.baz'));
        $this->jwt->shouldReceive('check')->once()->with(true)->andReturn($payload);
        $this->jwt->shouldReceive('checkSubjectModel')
                  ->once()
                  ->with('\Tymon\JWTAuth\Test\Stubs\LaravelUserStub', $payload)
                  ->andReturn(true);

        $this->provider->shouldReceive('getModel')
                       ->once()
                       ->andReturn('\Tymon\JWTAuth\Test\Stubs\LaravelUserStub');
        $this->provider->shouldReceive('retrieveById')
             ->once()
             ->with(1)
             ->andReturn((object) ['id' => 1]);

        $this->assertSame(1, $this->guard->userOrFail()->id);

        // check that the user is stored on the object next time round
        $this->assertSame(1, $this->guard->userOrFail()->id);
        $this->assertTrue($this->guard->check());
    }

    /**
     * @test
     */
    public function it_should_return_null_if_an_invalid_token_is_provided()
    {
        $this->jwt->shouldReceive('setRequest')->andReturn($this->jwt);
        $this->jwt->shouldReceive('getToken')->twice()->andReturn(new Token('invalid.token.here'));
        $this->jwt->shouldReceive('check')->twice()->andReturn(false);
        $this->jwt->shouldReceive('getPayload->get')->never();
        $this->provider->shouldReceive('retrieveById')->never();

        $this->assertNull($this->guard->user()); // once
        $this->assertFalse($this->guard->check()); // twice
    }

    /**
     * @test
     */
    public function it_should_return_null_if_no_token_is_provided()
    {
        $this->jwt->shouldReceive('setRequest')->andReturn($this->jwt);
        $this->jwt->shouldReceive('getToken')->andReturn(null);
        $this->jwt->shouldReceive('check')->never();
        $this->jwt->shouldReceive('getPayload->get')->never();
        $this->provider->shouldReceive('retrieveById')->never();

        $this->assertNull($this->guard->user());
        $this->assertFalse($this->guard->check());
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\UserNotDefinedException
     * @expectedExceptionMessage An error occurred
     */
    public function it_should_throw_an_exception_if_an_invalid_token_is_provided()
    {
        $this->jwt->shouldReceive('setRequest')->andReturn($this->jwt);
        $this->jwt->shouldReceive('getToken')->twice()->andReturn(new Token('invalid.token.here'));
        $this->jwt->shouldReceive('check')->twice()->andReturn(false);
        $this->jwt->shouldReceive('getPayload->get')->never();
        $this->provider->shouldReceive('retrieveById')->never();

        $this->assertFalse($this->guard->check()); // once
        $this->guard->userOrFail(); // twice, throws the exception
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\UserNotDefinedException
     * @expectedExceptionMessage An error occurred
     */
    public function it_should_throw_an_exception_if_no_token_is_provided()
    {
        $this->jwt->shouldReceive('setRequest')->andReturn($this->jwt);
        $this->jwt->shouldReceive('getToken')->andReturn(null);
        $this->jwt->shouldReceive('check')->never();
        $this->jwt->shouldReceive('getPayload->get')->never();
        $this->provider->shouldReceive('retrieveById')->never();

        $this->assertFalse($this->guard->check());
        $this->guard->userOrFail(); // throws the exception
    }

    /**
     * @test
     */
    public function it_should_return_a_token_if_credentials_are_ok_and_user_is_found()
    {
        $credentials = ['foo' => 'bar', 'baz' => 'bob'];
        $user = new LaravelUserStub;

        $this->provider->shouldReceive('retrieveByCredentials')
                       ->once()
                       ->with($credentials)
                       ->andReturn($user);

        $this->provider->shouldReceive('validateCredentials')
                       ->once()
                       ->with($user, $credentials)
                       ->andReturn(true);

        $this->jwt->shouldReceive('fromUser')
                  ->once()
                  ->with($user)
                  ->andReturn($token = new Token('foo.bar.baz'));

        $this->jwt->shouldReceive('setToken')
                  ->once()
                  ->with($token)
                  ->andReturnSelf();

        $this->jwt->shouldReceive('claims')
                  ->once()
                  ->with(['foo' => 'bar'])
                  ->andReturnSelf();

        $jwt = $this->guard->claims(['foo' => 'bar'])->attempt($credentials);

        $this->assertSame($this->guard->getLastAttempted(), $user);
        $this->assertTrue($jwt->matches($token));
        $this->assertSame((string) $jwt, 'foo.bar.baz');
    }

    /**
     * @test
     */
    public function it_should_return_true_if_credentials_are_ok_and_user_is_found_when_choosing_not_to_login()
    {
        $credentials = ['foo' => 'bar', 'baz' => 'bob'];
        $user = new LaravelUserStub;

        $this->provider->shouldReceive('retrieveByCredentials')
                       ->twice()
                       ->with($credentials)
                       ->andReturn($user);

        $this->provider->shouldReceive('validateCredentials')
                       ->twice()
                       ->with($user, $credentials)
                       ->andReturn(true);

        $this->assertTrue($this->guard->attempt($credentials, false)); // once
        $this->assertTrue($this->guard->validate($credentials)); // twice
    }

    /**
     * @test
     */
    public function it_should_return_false_if_credentials_are_invalid()
    {
        $credentials = ['foo' => 'bar', 'baz' => 'bob'];
        $user = new LaravelUserStub;

        $this->provider->shouldReceive('retrieveByCredentials')
                       ->once()
                       ->with($credentials)
                       ->andReturn($user);

        $this->provider->shouldReceive('validateCredentials')
                       ->once()
                       ->with($user, $credentials)
                       ->andReturn(false);

        $this->assertFalse($this->guard->attempt($credentials));
    }

    /**
     * @test
     */
    public function it_should_magically_call_the_jwt_instance()
    {
        $this->jwt->shouldReceive('builder')->andReturn(Mockery::mock(Builder::class));
        $this->assertInstanceOf(Builder::class, $this->guard->builder());
    }

    /**
     * @test
     */
    public function it_should_logout_the_user_by_invalidating_the_token()
    {
        $this->jwt->shouldReceive('setRequest')->andReturn($this->jwt);
        $this->jwt->shouldReceive('getToken')->once()->andReturn(new Token('foo.bar.baz'));
        $this->jwt->shouldReceive('unsetToken')->once();
        $this->jwt->shouldReceive('invalidate')->once()->andReturnSelf();

        $this->guard->logout();

        $this->assertNull($this->guard->getUser());
    }

    /**
     * @test
     */
    public function it_should_refresh_the_token()
    {
        $this->jwt->shouldReceive('setRequest')->andReturn($this->jwt);
        $this->jwt->shouldReceive('getToken')->twice()->andReturn(new Token('baz.bar.foo'));
        $this->jwt->shouldReceive('refresh')->twice()->andReturn($token = new Token('foo.bar.baz'));

        $this->assertTrue($token->matches($this->guard->refresh())); // once
        $this->assertSame((string) $this->guard->refresh(), 'foo.bar.baz'); // twice
    }

    /**
     * @test
     */
    public function it_should_invalidate_the_token()
    {
        $this->jwt->shouldReceive('setRequest')->andReturn($this->jwt);
        $this->jwt->shouldReceive('getToken')->once()->andReturn(new Token('foo.bar.baz'));
        $this->jwt->shouldReceive('invalidate')->once()->andReturnSelf();

        $this->guard->invalidate();
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\JWTException
     * @expectedExceptionMessage Token could not be parsed from the request.
     */
    public function it_should_throw_an_exception_if_there_is_no_token_present_when_required()
    {
        $this->jwt->shouldReceive('setRequest')->andReturn($this->jwt);
        $this->jwt->shouldReceive('getToken')->once()->andReturn(null);
        $this->jwt->shouldReceive('refresh')->never();

        $this->guard->refresh();
    }

    /**
     * @test
     */
    public function it_should_generate_a_token_by_id()
    {
        $user = new LaravelUserStub;

        $this->provider->shouldReceive('retrieveById')
                       ->once()
                       ->with(1)
                       ->andReturn($user);

        $this->jwt->shouldReceive('fromUser')
                  ->once()
                  ->with($user)
                  ->andReturn($token = new Token('foo.bar.baz'));

        $this->assertSame($token, $this->guard->tokenById(1));
    }

    /**
     * @test
     */
    public function it_should_not_generate_a_token_by_id()
    {
        $this->provider->shouldReceive('retrieveById')
                       ->once()
                       ->with(1)
                       ->andReturn(null);

        $this->assertNull($this->guard->tokenById(1));
    }

    /**
     * @test
     */
    public function it_should_authenticate_the_user_by_credentials_and_return_true_if_valid()
    {
        $credentials = ['foo' => 'bar', 'baz' => 'bob'];
        $user = new LaravelUserStub;

        $this->provider->shouldReceive('retrieveByCredentials')
                       ->once()
                       ->with($credentials)
                       ->andReturn($user);

        $this->provider->shouldReceive('validateCredentials')
                       ->once()
                       ->with($user, $credentials)
                       ->andReturn(true);

        $this->assertTrue($this->guard->once($credentials));
    }

    /**
     * @test
     */
    public function it_should_attempt_to_authenticate_the_user_by_credentials_and_return_false_if_invalid()
    {
        $credentials = ['foo' => 'bar', 'baz' => 'bob'];
        $user = new LaravelUserStub;

        $this->provider->shouldReceive('retrieveByCredentials')
                       ->once()
                       ->with($credentials)
                       ->andReturn($user);

        $this->provider->shouldReceive('validateCredentials')
                       ->once()
                       ->with($user, $credentials)
                       ->andReturn(false);

        $this->assertFalse($this->guard->once($credentials));
    }

    /**
     * @test
     */
    public function it_should_authenticate_the_user_by_id_and_return_boolean()
    {
        $user = new LaravelUserStub;

        $this->provider->shouldReceive('retrieveById')
                       ->twice()
                       ->with(1)
                       ->andReturn($user);

        $this->assertTrue($this->guard->onceUsingId(1)); // once
        $this->assertTrue($this->guard->byId(1)); // twice
    }

    /**
     * @test
     */
    public function it_should_not_authenticate_the_user_by_id_and_return_false()
    {
        $this->provider->shouldReceive('retrieveById')
                       ->twice()
                       ->with(1)
                       ->andReturn(null);

        $this->assertFalse($this->guard->onceUsingId(1)); // once
        $this->assertFalse($this->guard->byId(1)); // twice
    }

    /**
     * @test
     */
    public function it_should_create_a_token_from_a_user_object()
    {
        $user = new LaravelUserStub;

        $this->jwt->shouldReceive('fromUser')
                  ->once()
                  ->with($user)
                  ->andReturn($token = new Token('foo.bar.baz'));

        $this->jwt->shouldReceive('setToken')
                  ->once()
                  ->with($token)
                  ->andReturnSelf();

        $jwt = $this->guard->login($user);

        $this->assertTrue($jwt->matches($token));
        $this->assertSame('foo.bar.baz', (string) $jwt);
    }

    /**
     * @test
     */
    public function it_should_get_the_payload()
    {
        $this->jwt->shouldReceive('setRequest')->andReturnSelf();
        $this->jwt->shouldReceive('getToken')->once()->andReturn(new Token('foo.bar.baz'));
        $this->jwt->shouldReceive('payload')->once()->andReturn(Mockery::mock(Payload::class));

        $this->assertInstanceOf(Payload::class, $this->guard->payload());
    }
}
