<?php

/*
 * This file is part of jwt-auth
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Middleware;

use Mockery;
use Illuminate\Http\Response;
use Tymon\JWTAuth\Middleware\RefreshToken;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class RefreshTokenTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->auth = Mockery::mock('Tymon\JWTAuth\JWTAuth');
        $this->request = Mockery::mock('Illuminate\Http\Request');

        $this->middleware = new RefreshToken($this->auth);
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /** @test */
    public function it_should_refresh_a_token()
    {
        $parser = Mockery::mock('Tymon\JWTAuth\Http\TokenParser');
        $parser->shouldReceive('hasToken')->once()->andReturn(true);

        $this->auth->shouldReceive('parser')->andReturn($parser);

        $this->auth->parser()->shouldReceive('setRequest')->once()->with($this->request)->andReturn($this->auth->parser());
        $this->auth->shouldReceive('parseToken->refresh')->once()->andReturn('foo.bar.baz');

        $response = $this->middleware->handle($this->request, function () { return new Response; });

        $this->assertSame($response->headers->get('authorization'), 'Bearer foo.bar.baz');
    }

    /** @test */
    public function it_should_throw_a_bad_request_exception_if_token_not_provided()
    {
        $this->setExpectedException('Symfony\Component\HttpKernel\Exception\BadRequestHttpException');

        $parser = Mockery::mock('Tymon\JWTAuth\Http\TokenParser');
        $parser->shouldReceive('hasToken')->once()->andReturn(false);

        $this->auth->shouldReceive('parser')->andReturn($parser);
        $this->auth->parser()->shouldReceive('setRequest')->once()->with($this->request)->andReturn($this->auth->parser());

        $this->middleware->handle($this->request, function () {});
    }

    /** @test */
    public function it_should_throw_an_unauthorized_exception_if_token_invalid()
    {
        $this->setExpectedException('Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException');

        $parser = Mockery::mock('Tymon\JWTAuth\Http\TokenParser');
        $parser->shouldReceive('hasToken')->once()->andReturn(true);

        $this->auth->shouldReceive('parser')->andReturn($parser);

        $this->auth->parser()->shouldReceive('setRequest')->once()->with($this->request)->andReturn($this->auth->parser());
        $this->auth->shouldReceive('parseToken->refresh')->once()->andThrow(new TokenInvalidException);

        $this->middleware->handle($this->request, function () {});
    }
}
