<?php

/*
 * This file is part of jwt-auth.
 *
 * @author Sean Tymon <tymon148@gmail.com>
 * @copyright Copyright (c) Sean Tymon
 * @link https://github.com/tymondesigns/jwt-auth
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test\Providers\Auth;

use Mockery;
use Tymon\JWTAuth\Providers\Auth\Illuminate as Auth;

class IlluminateTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \Mockery\MockInterface
     */
    protected $authManager;

    /**
     * @var \Tymon\JWTAuth\Providers\Auth\Illuminate
     */
    protected $auth;

    public function setUp()
    {
        $this->authManager = Mockery::mock('Illuminate\Contracts\Auth\Guard');
        $this->auth = new Auth($this->authManager);
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /** @test */
    public function it_should_return_true_if_credentials_are_valid()
    {
        $this->authManager->shouldReceive('once')->once()->with(['email' => 'foo@bar.com', 'password' => 'foobar'])->andReturn(true);
        $this->assertTrue($this->auth->byCredentials(['email' => 'foo@bar.com', 'password' => 'foobar']));
    }

    /** @test */
    public function it_should_return_true_if_user_is_found()
    {
        $this->authManager->shouldReceive('onceUsingId')->once()->with(123)->andReturn(true);
        $this->assertTrue($this->auth->byId(123));
    }

    /** @test */
    public function it_should_return_false_if_user_is_not_found()
    {
        $this->authManager->shouldReceive('onceUsingId')->once()->with(123)->andReturn(false);
        $this->assertFalse($this->auth->byId(123));
    }

    /** @test */
    public function it_should_return_the_currently_authenticated_user()
    {
        $this->authManager->shouldReceive('user')->once()->andReturn((object) ['id' => 1]);
        $this->assertSame($this->auth->user()->id, 1);
    }
}
