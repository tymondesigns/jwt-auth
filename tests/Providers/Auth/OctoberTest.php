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
use October\Rain\Auth\Manager;
use Tymon\JWTAuth\Test\AbstractTestCase;
use Tymon\JWTAuth\Test\Stubs\OctoberStub;
use Tymon\JWTAuth\Providers\Auth\October as Auth;

class OctoberTest extends AbstractTestCase
{
    /**
     * @var \Mockery\MockInterface|\October\Rain\Auth\Manager
     */
    protected $october;

    /**
     * @var \Tymon\JWTAuth\Providers\Auth\October
     */
    protected $auth;

    public function setUp()
    {
        parent::setUp();

        $this->october = Mockery::mock(Manager::class);
        $this->auth = new Auth($this->october);
    }

    public function tearDown()
    {
        Mockery::close();

        parent::tearDown();
    }

    /** @test */
    public function it_should_return_true_if_credentials_are_valid()
    {
        $this->october->shouldReceive('findUserByCredentials')->once()->with(['email' => 'foo@bar.com', 'password' => 'foobar'])->andReturn(true);
        $this->assertTrue($this->auth->byCredentials(['email' => 'foo@bar.com', 'password' => 'foobar']));
    }

    /** @test */
    public function it_should_return_true_if_user_is_found()
    {
        $stub = new OctoberStub;
        $this->october->shouldReceive('findUserById')->once()->with(123)->andReturn($stub);
        $this->october->shouldReceive('setUser')->once()->with($stub);

        $this->assertTrue($this->auth->byId(123));
    }

    /** @test */
    public function it_should_return_false_if_user_is_not_found()
    {
        $this->october->shouldReceive('findUserById')->once()->with(321)->andReturn(null);
        $this->october->shouldReceive('setUser')->never();

        $this->assertFalse($this->auth->byId(321));
    }

    /** @test */
    public function it_should_return_the_currently_authenticated_user()
    {
        $this->october->shouldReceive('getUser')->once()->andReturn((object) ['id' => 1]);
        $this->assertSame($this->auth->user()->id, 1);
    }
}
