<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test\Middleware;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Http\Response;
use Mockery;
use Tymon\JWTAuth\JWTGuard;
use Tymon\JWTAuth\Test\Stubs\UserStub;
use Tymon\JWTAuth\Http\Middleware\AuthenticateAndRenew;

class AuthenticateAndRenewTest extends AbstractMiddlewareTest
{
    /**
     * @var \Tymon\JWTAuth\Http\Middleware\AuthenticateAndRenew
     */
    protected $middleware;

    public function setUp()
    {
        parent::setUp();

        $this->auth = Mockery::mock(AuthFactory::class);
        $this->middleware = new AuthenticateAndRenew($this->auth);
    }

    /** @test */
    public function it_should_authenticate_a_user_and_return_a_new_token()
    {
        $guard = Mockery::mock(JWTGuard::class);

        $this->auth->shouldReceive('guard')->andReturn($guard);
        $this->auth->shouldReceive('authenticate')->andReturn(new UserStub);
        $guard->shouldReceive('refresh')->andReturn('foo.bar.baz');

        $response = $this->middleware->handle($this->request, function () {
            return new Response;
        });

        $this->assertSame($response->headers->get('authorization'), 'Bearer foo.bar.baz');
    }

    /**
     * @test
     * @expectedException \Illuminate\Auth\AuthenticationException
     */
    public function it_should_throw_an_unauthorized_exception_if_authenticate_failed()
    {
        $guard = Mockery::mock(JWTGuard::class);

        $this->auth->shouldReceive('guard')->andReturn($guard);
        $this->auth->shouldReceive('authenticate')->andThrow(new AuthenticationException);

        $this->middleware->handle($this->request, function () {
            //
        });
    }
}
