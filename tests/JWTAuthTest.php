<?php

namespace Tymon\JWTAuth\Test;

use Mockery;
use Tymon\JWTAuth\JWTAuth;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Token;

class JWTAuthTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->user = Mockery::mock('Tymon\JWTAuth\Providers\User\UserInterface');
        $this->manager = Mockery::mock('Tymon\JWTAuth\JWTManager');
        $this->auth = Mockery::mock('Tymon\JWTAuth\Providers\Auth\AuthInterface');

        $this->jwtAuth = new JWTAuth($this->manager, $this->user, $this->auth, Request::create('/foo', 'GET'));
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /** @test */
    public function it_should_return_a_user_when_passing_a_token_containing_a_valid_subject_claim()
    {
        $payload = Mockery::mock('Tymon\JWTAuth\Payload');
        $payload->shouldReceive('offsetGet')->once()->andReturn(1);

        $this->manager->shouldReceive('decode')->once()->andReturn($payload);
        $this->user->shouldReceive('getBy')->once()->andReturn((object) ['id' => 1]);

        $user = $this->jwtAuth->toUser('foo.bar.baz');

        $this->assertEquals(1, $user->id);
    }

    /** @test */
    public function it_should_return_false_when_passing_a_token_containing_an_invalid_subject_claim()
    {
        $payload = Mockery::mock('Tymon\JWTAuth\Payload');
        $payload->shouldReceive('offsetGet')->once()->andReturn(1);

        $this->manager->shouldReceive('decode')->once()->andReturn($payload);
        $this->user->shouldReceive('getBy')->once()->andReturn(false);

        $user = $this->jwtAuth->toUser('foo.bar.baz');

        $this->assertFalse($user);
    }

    /** @test */
    public function it_should_return_a_token_when_passing_a_user()
    {
        $this->manager->shouldReceive('getPayloadFactory->make')->once()->andReturn(Mockery::mock('Tymon\JWTAuth\Payload'));
        $this->manager->shouldReceive('encode->get')->once()->andReturn('foo.bar.baz');

        $token = $this->jwtAuth->fromUser((object) ['id' => 1]);

        $this->assertEquals($token, 'foo.bar.baz');
    }

    /** @test */
    public function it_should_return_a_token_when_passing_valid_credentials_to_attempt_method()
    {
        $this->manager->shouldReceive('getPayloadFactory->make')->once()->andReturn(Mockery::mock('Tymon\JWTAuth\Payload'));
        $this->manager->shouldReceive('encode->get')->once()->andReturn('foo.bar.baz');

        $this->auth->shouldReceive('byCredentials')->once()->andReturn(true);
        $this->auth->shouldReceive('user')->once()->andReturn((object) ['id' => 1]);

        $token = $this->jwtAuth->attempt();

        $this->assertEquals($token, 'foo.bar.baz');
    }

    /** @test */
    public function it_should_return_false_when_passing_invalid_credentials_to_attempt_method()
    {
        $this->manager->shouldReceive('encode->get')->never();
        $this->auth->shouldReceive('byCredentials')->once()->andReturn(false);
        $this->auth->shouldReceive('user')->never();

        $token = $this->jwtAuth->attempt();

        $this->assertFalse($token);
    }

    /** @test */
    public function it_should_throw_an_exception_when_not_providing_a_token()
    {
        $this->setExpectedException('Tymon\JWTAuth\Exceptions\JWTException');

        $user = $this->jwtAuth->toUser();
    }

    /** @test */
    public function it_should_return_the_owning_user_from_a_token_containing_an_existing_user()
    {
        $payload = Mockery::mock('Tymon\JWTAuth\Payload');
        $payload->shouldReceive('get')->once()->with('sub')->andReturn(1);

        $this->manager->shouldReceive('decode')->once()->andReturn($payload);

        $this->auth->shouldReceive('byId')->once()->with(1)->andReturn(true);
        $this->auth->shouldReceive('user')->once()->andReturn((object) ['id' => 1]);

        $user = $this->jwtAuth->authenticate('foo.bar.baz');

        $this->assertEquals($user->id, 1);
    }

    /** @test */
    public function it_should_return_false_when_passing_a_token_not_containing_an_existing_user()
    {
        $payload = Mockery::mock('Tymon\JWTAuth\Payload');
        $payload->shouldReceive('get')->once()->with('sub')->andReturn(1);

        $this->manager->shouldReceive('decode')->once()->andReturn($payload);

        $this->auth->shouldReceive('byId')->once()->with(1)->andReturn(false);
        $this->auth->shouldReceive('user')->never();

        $user = $this->jwtAuth->authenticate('foo.bar.baz');

        $this->assertFalse($user);
    }

    /** @test */
    public function it_should_refresh_a_token()
    {
        $newToken = Mockery::mock('Tymon\JWTAuth\Token');
        $newToken->shouldReceive('get')->once()->andReturn('baz.bar.foo');

        $this->manager->shouldReceive('refresh')->once()->andReturn($newToken);

        $result = $this->jwtAuth->setToken('foo.bar.baz')->refresh();

        $this->assertEquals($result, 'baz.bar.foo');
    }

    /** @test */
    public function it_should_invalidate_a_token()
    {
        $this->manager->shouldReceive('invalidate')->once()->andReturn(true);

        $result = $this->jwtAuth->invalidate('foo.bar.baz');

        $this->assertTrue($result);
    }

    /** @test */
    public function it_should_retrieve_the_token_from_the_auth_header()
    {
        $request = Request::create('/foo', 'GET');
        $request->headers->set('authorization', 'Bearer foo.bar.baz');
        $jwtAuth = new JWTAuth($this->manager, $this->user, $this->auth, $request);

        $this->assertInstanceOf('Tymon\JWTAuth\Token', $jwtAuth->parseToken()->getToken());
        $this->assertEquals($jwtAuth->getToken(), 'foo.bar.baz');
    }

    /** @test */
    public function it_should_retrieve_the_token_from_the_query_string()
    {
        $request = Request::create('/foo', 'GET', ['token' => 'foo.bar.baz']);
        $jwtAuth = new JWTAuth($this->manager, $this->user, $this->auth, $request);

        $this->assertInstanceOf('Tymon\JWTAuth\Token', $jwtAuth->parseToken()->getToken());
        $this->assertEquals($jwtAuth->getToken(), 'foo.bar.baz');
    }

    /** @test */
    public function it_should_throw_an_exception_when_token_not_present_in_request()
    {
        $this->setExpectedException('Tymon\JWTAuth\Exceptions\JWTException');

        $request = Request::create('/foo', 'GET');
        $jwtAuth = new JWTAuth($this->manager, $this->user, $this->auth, $request);

        $jwtAuth->parseToken();
    }

    /** @test */
    public function it_should_return_false_when_no_token_is_set()
    {
        $this->assertFalse($this->jwtAuth->getToken());
    }

    /** @test */
    public function it_should_set_the_identifier()
    {
        $this->jwtAuth->setIdentifier('foo');

        $this->assertEquals($this->jwtAuth->getIdentifier(), 'foo');
    }

    /** @test */
    public function it_should_magically_call_the_manager()
    {
        $this->manager->shouldReceive('getBlacklist')->andReturn(new \StdClass);

        $blacklist = $this->jwtAuth->getBlacklist();

        $this->assertInstanceOf('StdClass', $blacklist);
    }

    /** @test */
    public function it_should_set_the_request()
    {
        $request = Request::create('/foo', 'GET', ['token' => 'some.random.token']);

        $token = $this->jwtAuth->setRequest($request)->getToken();

        $this->assertEquals('some.random.token', $token);
    }

    /** @test */
    public function it_should_get_the_manager_instance()
    {
        $manager = $this->jwtAuth->manager();
        $this->assertInstanceOf('Tymon\JWTAuth\JWTManager', $manager);
    }
}
