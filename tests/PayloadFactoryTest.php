<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test\Providers\JWT;

use Mockery;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Claims\JwtId;
use Tymon\JWTAuth\Claims\Custom;
use Tymon\JWTAuth\Claims\Issuer;
use Tymon\JWTAuth\Claims\Subject;
use Tymon\JWTAuth\PayloadFactory;
use Tymon\JWTAuth\Claims\IssuedAt;
use Tymon\JWTAuth\Claims\NotBefore;
use Tymon\JWTAuth\Claims\Expiration;

class PayloadFactoryTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \Tymon\JWTAuth\Claims\Factory|\Mockery\MockInterface
     */
    protected $claimFactory;

    /**
     * @var \Tymon\JWTAuth\Validators\PayloadValidator|\Mockery\MockInterface
     */
    protected $validator;

    /**
     * @var \Tymon\JWTAuth\PayloadFactory
     */
    protected $factory;

    public function setUp()
    {
        parent::setUp();

        Carbon::setTestNow(Carbon::createFromTimeStampUTC(123));

        $this->claimFactory = Mockery::mock('Tymon\JWTAuth\Claims\Factory');
        $this->validator = Mockery::mock('Tymon\JWTAuth\Validators\PayloadValidator');
        $this->factory = new PayloadFactory($this->claimFactory, Request::create('/foo', 'GET'), $this->validator);
    }

    public function tearDown()
    {
        Mockery::close();

        parent::tearDown();
    }

    /** @test */
    public function it_should_return_a_payload_when_passing_an_array_of_claims_to_make_method()
    {
        $this->validator->shouldReceive('setRefreshFlow->check');

        $expTime = 123 + 3600;

        $this->claimFactory->shouldReceive('get')->once()->with('sub', 1)->andReturn(new Subject(1));
        $this->claimFactory->shouldReceive('get')->once()->with('iss', Mockery::any())->andReturn(new Issuer('/foo'));
        $this->claimFactory->shouldReceive('get')->once()->with('iat', 123)->andReturn(new IssuedAt(123));
        $this->claimFactory->shouldReceive('get')->once()->with('jti', 'foo')->andReturn(new JwtId('foo'));
        $this->claimFactory->shouldReceive('get')->once()->with('nbf', 123)->andReturn(new NotBefore(123));
        $this->claimFactory->shouldReceive('get')->once()->with('exp', $expTime)->andReturn(new Expiration($expTime));

        $payload = $this->factory->make(['sub' => 1, 'jti' => 'foo', 'iat' => 123]);

        $this->assertEquals($payload->get('sub'), 1);
        $this->assertEquals($payload->get('iat'), 123);
        $this->assertEquals($payload['exp'], $expTime);

        $this->assertInstanceOf('Tymon\JWTAuth\Payload', $payload);
    }

    /** @test **/
    public function it_should_check_custom_claim_keys_accurately_and_accept_numeric_claims()
    {
        $this->validator->shouldReceive('setRefreshFlow->check');

        $this->claimFactory->shouldReceive('get')->once()->with('iss', Mockery::any())->andReturn(new Issuer('/foo'));
        $this->claimFactory->shouldReceive('get')->once()->with('exp', 123 + 3600)->andReturn(new Expiration(123 + 3600));
        $this->claimFactory->shouldReceive('get')->once()->with('iat', 123)->andReturn(new IssuedAt(123));
        $this->claimFactory->shouldReceive('get')->once()->with('jti', Mockery::any())->andReturn(new JwtId('foo'));
        $this->claimFactory->shouldReceive('get')->once()->with('nbf', 123)->andReturn(new NotBefore(123));
        $this->claimFactory->shouldReceive('get')->once()->with(1, 'claim one')->andReturn(new Custom(1, 'claim one'));

        $payload = $this->factory->make([1 => 'claim one']);

        // if the checker doesn't compare defaults properly, numeric-keyed claims might be ignored
        $this->assertEquals('claim one', $payload->get(1));
        // iat is $defaultClaims[1], so verify it wasn't skipped due to a bad k-v comparison
        $this->assertEquals(123, $payload->get('iat'));
    }

    /** @test */
    public function it_should_return_a_payload_when_chaining_claim_methods()
    {
        $this->validator->shouldReceive('setRefreshFlow->check');

        $this->claimFactory->shouldReceive('get')->once()->with('sub', 1)->andReturn(new Subject(1));
        $this->claimFactory->shouldReceive('get')->once()->with('iss', Mockery::any())->andReturn(new Issuer('/foo'));
        $this->claimFactory->shouldReceive('get')->once()->with('exp', 123 + 3600)->andReturn(new Expiration(123 + 3600));
        $this->claimFactory->shouldReceive('get')->once()->with('iat', 123)->andReturn(new IssuedAt(123));
        $this->claimFactory->shouldReceive('get')->once()->with('jti', Mockery::any())->andReturn(new JwtId('foo'));
        $this->claimFactory->shouldReceive('get')->once()->with('nbf', 123)->andReturn(new NotBefore(123));
        $this->claimFactory->shouldReceive('get')->once()->with('foo', 'baz')->andReturn(new Custom('foo', 'baz'));

        $payload = $this->factory->sub(1)->foo('baz')->make();

        $this->assertEquals($payload['sub'], 1);
        $this->assertEquals($payload->get('jti'), 'foo');
        $this->assertEquals($payload->get('foo'), 'baz');

        $this->assertInstanceOf('Tymon\JWTAuth\Payload', $payload);
    }

    /** @test */
    public function it_should_return_a_payload_when_passing_miltidimensional_claims()
    {
        $this->validator->shouldReceive('setRefreshFlow->check');
        $userObject = ['name' => 'example'];

        $this->claimFactory->shouldReceive('get')->once()->with('sub', $userObject)->andReturn(new Subject($userObject));
        $this->claimFactory->shouldReceive('get')->once()->with('iss', Mockery::any())->andReturn(new Issuer('/foo'));
        $this->claimFactory->shouldReceive('get')->once()->with('exp', Mockery::any())->andReturn(new Expiration(123 + 3600));
        $this->claimFactory->shouldReceive('get')->once()->with('iat', Mockery::any())->andReturn(new IssuedAt(123));
        $this->claimFactory->shouldReceive('get')->once()->with('jti', Mockery::any())->andReturn(new JwtId('foo'));
        $this->claimFactory->shouldReceive('get')->once()->with('nbf', Mockery::any())->andReturn(new NotBefore(123));
        $this->claimFactory->shouldReceive('get')->once()->with('foo', ['bar' => [0, 0, 0]])->andReturn(new Custom('foo', ['bar' => [0, 0, 0]]));

        $payload = $this->factory->sub($userObject)->foo(['bar' => [0, 0, 0]])->make();

        $this->assertEquals($payload->get('sub'), $userObject);
        $this->assertEquals($payload->get('foo'), ['bar' => [0, 0, 0]]);

        $this->assertInstanceOf('Tymon\JWTAuth\Payload', $payload);
    }

    /** @test */
    public function it_should_set_the_ttl()
    {
        $this->factory->setTTL(12345);

        $this->assertEquals($this->factory->getTTL(), 12345);
    }
}
