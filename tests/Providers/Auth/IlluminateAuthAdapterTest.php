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
use Tymon\JWTAuth\Providers\Auth\IlluminateAuthAdapter;

class IlluminateAuthAdapterTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->authManager = Mockery::mock('Illuminate\Auth\AuthManager');
        $this->auth = new IlluminateAuthAdapter($this->authManager);
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
    public function it_should_bubble_exceptions_from_auth()
    {
        $this->authManager->shouldReceive('onceUsingId')->once()->with(123)->andThrow(new \Exception('Some auth failure'));
        $this->setExpectedException('Exception', 'Some auth failure');
        $this->auth->byId(123);
    }

    /** @test */
    public function it_should_return_the_currently_authenticated_user()
    {
        $this->authManager->shouldReceive('user')->once()->andReturn((object) ['id' => 1]);
        $this->assertEquals($this->auth->user()->id, 1);
    }
}
