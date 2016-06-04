<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test;

use Mockery;
use Tymon\JWTAuth\Factory;
use Tymon\JWTAuth\Payload;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Claims\JwtId;
use Tymon\JWTAuth\Claims\Custom;
use Tymon\JWTAuth\Claims\Issuer;
use Tymon\JWTAuth\Claims\Subject;
use Tymon\JWTAuth\Claims\IssuedAt;
use Tymon\JWTAuth\Claims\Collection;
use Tymon\JWTAuth\Claims\NotBefore;
use Tymon\JWTAuth\Claims\Expiration;
use Tymon\JWTAuth\Validators\PayloadValidator;
use Tymon\JWTAuth\Claims\Factory as ClaimFactory;

class FactoryTest extends AbstractTestCase
{
    /**
     * @var \Mockery\MockInterface|\Tymon\JWTAuth\Claims\Factory
     */
    protected $claimFactory;

    /**
     * @var \Mockery\MockInterface|\Tymon\JWTAuth\Validators\PayloadValidator
     */
    protected $validator;

    /**
     * @var \Tymon\JWTAuth\Factory
     */
    protected $factory;

    public function setUp()
    {
        parent::setUp();

        $this->claimFactory = Mockery::mock(ClaimFactory::class);
        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->factory = new Factory($this->claimFactory, Request::create('/foo', 'GET'), $this->validator);
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

        $expTime = $this->testNowTimestamp + 3600;

        $this->claimFactory->shouldReceive('get')->once()->with('sub', 1)->andReturn(new Subject(1));
        $this->claimFactory->shouldReceive('get')->once()->with('iss', Mockery::any())->andReturn(new Issuer('/foo'));
        $this->claimFactory->shouldReceive('get')->once()->with('iat', 123)->andReturn(new IssuedAt(123));
        $this->claimFactory->shouldReceive('get')->once()->with('jti', 'foo')->andReturn(new JwtId('foo'));
        $this->claimFactory->shouldReceive('get')->once()->with('nbf', 123)->andReturn(new NotBefore(123));
        $this->claimFactory->shouldReceive('get')->once()->with('exp', $expTime)->andReturn(new Expiration($expTime));

        $payload = $this->factory->customClaims(['sub' => 1, 'jti' => 'foo', 'iat' => 123, 'nbf' => 123])->make();

        $this->assertSame($payload->get('sub'), 1);
        $this->assertSame($payload->get('iat'), 123);
        $this->assertSame($payload['exp'], $expTime);

        $this->assertInstanceOf(Payload::class, $payload);
    }

    /** @test */
    public function it_should_return_a_payload_when_chaining_claim_methods()
    {
        $this->validator->shouldReceive('setRefreshFlow->check');

        $this->claimFactory->shouldReceive('get')->once()->with('sub', 1)->andReturn(new Subject(1));
        $this->claimFactory->shouldReceive('get')->once()->with('iss', Mockery::any())->andReturn(new Issuer('/foo'));
        $this->claimFactory->shouldReceive('get')->once()->with('exp', $this->testNowTimestamp + 3600)->andReturn(new Expiration($this->testNowTimestamp + 3600));
        $this->claimFactory->shouldReceive('get')->once()->with('iat', $this->testNowTimestamp)->andReturn(new IssuedAt($this->testNowTimestamp));
        $this->claimFactory->shouldReceive('get')->once()->with('jti', Mockery::any())->andReturn(new JwtId('foo'));
        $this->claimFactory->shouldReceive('get')->once()->with('nbf', $this->testNowTimestamp)->andReturn(new NotBefore($this->testNowTimestamp));
        $this->claimFactory->shouldReceive('get')->once()->with('foo', 'baz')->andReturn(new Custom('foo', 'baz'));

        $payload = $this->factory->sub(1)->foo('baz')->make();

        $this->assertSame($payload['sub'], 1);
        $this->assertSame($payload->get('jti'), 'foo');
        $this->assertSame($payload->get('foo'), 'baz');

        $this->assertInstanceOf(Payload::class, $payload);
    }

    /** @test */
    public function it_should_return_a_payload_when_passing_miltidimensional_array_as_custom_claim_to_make_method()
    {
        $this->validator->shouldReceive('setRefreshFlow->check');

        $this->claimFactory->shouldReceive('get')->once()->with('sub', 1)->andReturn(new Subject(1));
        $this->claimFactory->shouldReceive('get')->once()->with('iss', Mockery::any())->andReturn(new Issuer('/foo'));
        $this->claimFactory->shouldReceive('get')->once()->with('exp', Mockery::any())->andReturn(new Expiration($this->testNowTimestamp + 3600));
        $this->claimFactory->shouldReceive('get')->once()->with('iat', Mockery::any())->andReturn(new IssuedAt($this->testNowTimestamp));
        $this->claimFactory->shouldReceive('get')->once()->with('jti', Mockery::any())->andReturn(new JwtId('foo'));
        $this->claimFactory->shouldReceive('get')->once()->with('nbf', Mockery::any())->andReturn(new NotBefore($this->testNowTimestamp));
        $this->claimFactory->shouldReceive('get')->once()->with('foo', ['bar' => [0, 0, 0]])->andReturn(new Custom('foo', ['bar' => [0, 0, 0]]));

        $payload = $this->factory->sub(1)->foo(['bar' => [0, 0, 0]])->make();

        $this->assertSame($payload->get('sub'), 1);
        $this->assertSame($payload->get('foo'), ['bar' => [0, 0, 0]]);
        $this->assertSame($payload->get('foo.bar'), [0, 0, 0]);

        $this->assertInstanceOf(Payload::class, $payload);
    }

    /** @test */
    public function it_should_exclude_the_exp_claim_when_setting_ttl_to_null()
    {
        $this->validator->shouldReceive('setRefreshFlow->check');

        $this->claimFactory->shouldReceive('get')->once()->with('sub', 1)->andReturn(new Subject(1));
        $this->claimFactory->shouldReceive('get')->once()->with('iss', Mockery::any())->andReturn(new Issuer('/foo'));
        $this->claimFactory->shouldReceive('get')->once()->with('iat', Mockery::any())->andReturn(new IssuedAt($this->testNowTimestamp));
        $this->claimFactory->shouldReceive('get')->once()->with('jti', Mockery::any())->andReturn(new JwtId('foo'));
        $this->claimFactory->shouldReceive('get')->once()->with('nbf', Mockery::any())->andReturn(new NotBefore($this->testNowTimestamp));

        $payload = $this->factory->setTTL(null)->sub(1)->make();

        $this->assertNull($payload->get('exp'));

        $this->assertInstanceOf(Payload::class, $payload);
    }

    /** @test */
    public function it_should_set_the_ttl()
    {
        $this->factory->setTTL(12345);

        $this->assertSame($this->factory->getTTL(), 12345);
    }

    /** @test */
    public function it_should_set_the_default_claims()
    {
        $this->factory->setDefaultClaims(['sub', 'iat']);

        $this->assertSame($this->factory->getDefaultClaims(), ['sub', 'iat']);
    }

    /** @test */
    public function it_should_get_payload_with_a_predefined_collection_of_claims()
    {
        $this->validator->shouldReceive('setRefreshFlow->check');

        $claims = [
            'sub' => new Subject(1),
            'iss' => new Issuer('http://example.com'),
            'exp' => new Expiration($this->testNowTimestamp + 3600),
            'nbf' => new NotBefore($this->testNowTimestamp),
            'iat' => new IssuedAt($this->testNowTimestamp),
            'jti' => new JwtId('foo'),
        ];

        $payload = $this->factory->withClaims(Collection::make($claims));

        $this->assertInstanceOf(Payload::class, $payload);
        $this->assertSame($payload->get('sub'), 1);
    }

    /** @test */
    public function it_should_get_the_validator()
    {
        $this->assertInstanceOf(PayloadValidator::class, $this->factory->validator());
    }

    /** @test */
    public function it_should_set_the_request()
    {
        $this->factory->setRequest(Request::create('/foobar', 'GET'));
    }
}
