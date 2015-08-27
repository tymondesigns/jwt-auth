<?php

/*
 * This file is part of jwt-auth
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test\Middleware;

use Mockery;
use Tymon\JWTAuth\Test\Stubs\UserStub;
use Tymon\JWTAuth\Middleware\Authenticate;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class AuthenticateTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->auth = Mockery::mock('Tymon\JWTAuth\JWTAuth');
        $this->request = Mockery::mock('Illuminate\Http\Request');

        $this->middleware = new Authenticate($this->auth);
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /** @test */
    public function it_should_authenticate_a_user()
    {
        $parser = Mockery::mock('Tymon\JWTAuth\Http\TokenParser');
        $parser->shouldReceive('hasToken')->once()->andReturn(true);

        $this->auth->shouldReceive('parser')->andReturn($parser);

        $this->auth->parser()->shouldReceive('setRequest')->once()->with($this->request)->andReturn($this->auth->parser());
        $this->auth->shouldReceive('authenticate')->once()->andReturn(new UserStub);

        $this->middleware->handle($this->request, function () {});
    }
}
