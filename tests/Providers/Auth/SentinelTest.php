<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test\Providers\Auth;

use Mockery;
use Cartalyst\Sentinel\Sentinel;
use Tymon\JWTAuth\Test\AbstractTestCase;
use Tymon\JWTAuth\Test\Stubs\SentinelStub;
use Tymon\JWTAuth\Providers\Auth\Sentinel as Auth;

class SentinelTest extends AbstractTestCase
{
    /**
     * @var \Mockery\MockInterface|\Cartalyst\Sentinel\Sentinel
     */
    protected $sentinel;

    /**
     * @var \Tymon\JWTAuth\Providers\Auth\Sentinel
     */
    protected $auth;

    public function setUp()
    {
        parent::setUp();

        $this->sentinel = Mockery::mock(Sentinel::class);
        $this->auth = new Auth($this->sentinel);
    }

    /** @test */
    public function it_should_return_true_if_credentials_are_valid()
    {
        $this->sentinel->shouldReceive('stateless')->once()->with(['email' => 'foo@bar.com', 'password' => 'foobar'])->andReturn(true);
        $this->assertTrue($this->auth->byCredentials(['email' => 'foo@bar.com', 'password' => 'foobar']));
    }

    /** @test */
    public function it_should_return_true_if_user_is_found()
    {
        $stub = new SentinelStub;
        $this->sentinel->shouldReceive('getUserRepository->findById')->once()->with(123)->andReturn($stub);
        $this->sentinel->shouldReceive('setUser')->once()->with($stub);

        $this->assertTrue($this->auth->byId(123));
    }

    /** @test */
    public function it_should_return_false_if_user_is_not_found()
    {
        $this->sentinel->shouldReceive('getUserRepository->findById')->once()->with(321)->andReturn(false);
        $this->sentinel->shouldReceive('setUser')->never();

        $this->assertFalse($this->auth->byId(321));
    }

    /** @test */
    public function it_should_return_the_currently_authenticated_user()
    {
        $this->sentinel->shouldReceive('getUser')->once()->andReturn(new SentinelStub);
        $this->assertSame($this->auth->user()->getUserId(), 123);
    }
}
