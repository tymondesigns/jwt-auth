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

use Illuminate\Http\Response;
use Mockery;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Http\Middleware\AuthenticateAndRenew;
use Tymon\JWTAuth\Http\Parser\Parser;
use Tymon\JWTAuth\Test\Stubs\UserStub;

class AuthenticateAndRenewTest extends AbstractMiddlewareTest
{
    /**
     * @var \Tymon\JWTAuth\Http\Middleware\Authenticate|\Tymon\JWTAuth\Http\Middleware\AuthenticateAndRenew
     */
    protected $middleware;

    public function setUp(): void
    {
        parent::setUp();

        $this->middleware = new AuthenticateAndRenew($this->auth);
    }

    /** @test */
    public function it_should_authenticate_a_user_and_return_a_new_token()
    {
        $parser = Mockery::mock(Parser::class);
        $parser->shouldReceive('hasToken')->once()->andReturn(true);
        $this->auth->shouldReceive('parser')->andReturn($parser);
        $this->auth->parser()->shouldReceive('setRequest')->once()->with($this->request)->andReturn($this->auth->parser());

        $this->auth->shouldReceive('parseToken->authenticate')->once()->andReturn(new UserStub);

        $this->auth->shouldReceive('refresh')->once()->andReturn('foo.bar.baz');

        $response = $this->middleware->handle($this->request, function () {
            return new Response;
        });

        $this->assertSame($response->headers->get('authorization'), 'Bearer foo.bar.baz');
    }

    /** @test */
    public function it_should_throw_an_unauthorized_exception_if_token_not_provided()
    {
        $this->expectException(UnauthorizedHttpException::class);

        $parser = Mockery::mock(Parser::class);
        $parser->shouldReceive('hasToken')->once()->andReturn(false);

        $this->auth->shouldReceive('parser')->andReturn($parser);
        $this->auth->parser()->shouldReceive('setRequest')->once()->with($this->request)->andReturn($this->auth->parser());

        $this->middleware->handle($this->request, function () {
            //
        });
    }

    /** @test */
    public function it_should_throw_an_unauthorized_exception_if_token_invalid()
    {
        $this->expectException(UnauthorizedHttpException::class);

        $parser = Mockery::mock(Parser::class);
        $parser->shouldReceive('hasToken')->once()->andReturn(true);

        $this->auth->shouldReceive('parser')->andReturn($parser);

        $this->auth->parser()->shouldReceive('setRequest')->once()->with($this->request)->andReturn($this->auth->parser());
        $this->auth->shouldReceive('parseToken->authenticate')->once()->andThrow(new TokenInvalidException);

        $this->middleware->handle($this->request, function () {
            //
        });
    }
}
