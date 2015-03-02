<?php

namespace Tymon\JWTAuth\Test;

use Mockery;
use Tymon\JWTAuth\JWTAuthFilter;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class JWTAuthFilterTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->events = Mockery::mock('Illuminate\Events\Dispatcher');
        $this->auth = Mockery::mock('Tymon\JWTAuth\JWTAuth');
        $this->filter = new JWTAuthFilter($this->events, $this->auth);

        $this->route = Mockery::mock('Illuminate\Routing\Router');
        $this->request = Mockery::mock('Illuminate\Http\Request');
        $this->response = Mockery::mock('alias:Response');
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /** @test */
    public function it_should_fire_an_event_when_no_token_is_available()
    {
        $this->auth->shouldReceive('getToken')->once()->andReturn(false);

        $this->events->shouldReceive('fire')->once()->with('tymon.jwt.absent', [], true);
        $this->response->shouldReceive('json')->with(['error' => 'token_not_provided'], 400);

        $this->filter->filter($this->route, $this->request);
    }

    /** @test */
    public function it_should_fire_an_event_when_the_token_has_expired()
    {
        $exception = new TokenExpiredException;

        $this->auth->shouldReceive('getToken')->once()->andReturn('foo');
        $this->auth->shouldReceive('toUser')->once()->with('foo')->andThrow($exception);

        $this->events->shouldReceive('fire')->once()->with('tymon.jwt.expired', [$exception], true);
        $this->response->shouldReceive('json')->with(['error' => 'token_expired'], 401);

        $this->filter->filter($this->route, $this->request);
    }

    /** @test */
    public function it_should_fire_an_event_when_the_token_is_invalid()
    {
        $exception = new TokenInvalidException;

        $this->auth->shouldReceive('getToken')->once()->andReturn('foo');
        $this->auth->shouldReceive('toUser')->once()->with('foo')->andThrow($exception);

        $this->events->shouldReceive('fire')->once()->with('tymon.jwt.invalid', [$exception], true);
        $this->response->shouldReceive('json')->with(['error' => 'token_invalid'], 400);

        $this->filter->filter($this->route, $this->request);
    }

    /** @test */
    public function it_should_fire_an_event_when_no_user_is_found()
    {
        $this->auth->shouldReceive('getToken')->once()->andReturn('foo');
        $this->auth->shouldReceive('toUser')->once()->with('foo')->andReturn(false);

        $this->events->shouldReceive('fire')->once()->with('tymon.jwt.user_not_found', [], true);
        $this->response->shouldReceive('json')->with(['error' => 'user_not_found'], 404);

        $this->filter->filter($this->route, $this->request);
    }

    /** @test */
    public function it_should_fire_an_event_when_the_token_has_been_decoded_and_user_is_found()
    {
        $user = (object) ['id' => 1];

        $this->auth->shouldReceive('getToken')->once()->andReturn('foo');
        $this->auth->shouldReceive('toUser')->once()->with('foo')->andReturn($user);

        $this->events->shouldReceive('fire')->once()->with('tymon.jwt.valid', $user);
        $this->response->shouldReceive('json')->never();

        $this->filter->filter($this->route, $this->request);
    }
}
