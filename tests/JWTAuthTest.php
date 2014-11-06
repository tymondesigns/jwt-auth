<?php

namespace Tymon\JWTAuth\Test;

use Mockery;
use Tymon\JWTAuth\JWTAuth;
use Illuminate\Http\Request;

class JWTAuthTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->user = Mockery::mock('Tymon\JWTAuth\User\UserInterface');
        $this->jwt = Mockery::mock('Tymon\JWTAuth\JWT\JWTInterface');
        $this->auth = Mockery::mock('Tymon\JWTAuth\Auth\AuthInterface');

        $this->jwtAuth = new JWTAuth($this->user, $this->jwt, $this->auth, Request::create('/foo', 'GET'));
    }

    /** @test */
    public function it_should_return_a_user_when_passing_a_token_containing_a_valid_subject_claim()
    {
        $this->jwt->shouldReceive('decode')->once()->with('foo');
        $this->jwt->shouldReceive('getSubject')->once()->andReturn(1);
        $this->user->shouldReceive('getBy')->once()->andReturn((object) ['id' => 1]);

        $user = $this->jwtAuth->toUser('foo');

        $this->assertEquals(1, $user->id);
    }

    /** @test */
    public function it_should_return_false_when_passing_a_token_containing_an_invalid_subject_claim()
    {
        $this->jwt->shouldReceive('decode')->once()->with('foo');
        $this->jwt->shouldReceive('getSubject')->once()->andReturn(1);
        $this->user->shouldReceive('getBy')->once()->andReturnNull();

        $user = $this->jwtAuth->toUser('foo');

        $this->assertFalse($user);
    }

    /** @test */
    public function it_should_return_a_token_when_passing_a_user()
    {
        $this->jwt->shouldReceive('encode->get')->once()->andReturn('foo');

        $token = $this->jwtAuth->fromUser((object) ['id' => 1]);

        $this->assertEquals($token, 'foo');
    }

    /** @test */
    public function it_should_return_a_token_when_passing_valid_credentials_to_attempt_method()
    {
        $this->jwt->shouldReceive('encode->get')->once()->andReturn('foo');
        $this->auth->shouldReceive('check')->once()->andReturn(true);
        $this->auth->shouldReceive('user')->once()->andReturn((object) ['id' => 1]);

        $token = $this->jwtAuth->attempt();

        $this->assertEquals($token, 'foo');
    }

    /** @test */
    public function it_should_return_false_when_passing_invalid_credentials_to_attempt_method()
    {
        $this->jwt->shouldReceive('encode->get')->never();
        $this->auth->shouldReceive('check')->once()->andReturn(false);
        $this->auth->shouldReceive('user')->never();

        $token = $this->jwtAuth->attempt();

        $this->assertFalse($token);
    }

    /** @test */
    public function it_should_return_the_owning_user_from_a_token_containing_an_existing_user()
    {
        $this->jwt->shouldReceive('getSubject')->once()->andReturn(1);
        $this->auth->shouldReceive('checkUsingId')->once()->andReturn((object) ['id' => 1]);

        $user = $this->jwtAuth->login('foo');

        $this->assertEquals($user->id, 1);
    }

    /** @test */
    public function it_should_return_false_when_passing_a_token_not_containing_an_existing_user()
    {
        $this->jwt->shouldReceive('getSubject')->once()->andReturn(2);
        $this->auth->shouldReceive('checkUsingId')->once()->andReturn(false);

        $user = $this->jwtAuth->login('foo');

        $this->assertFalse($user);
    }
}