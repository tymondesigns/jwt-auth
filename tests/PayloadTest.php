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
use Tymon\JWTAuth\Payload;
use Tymon\JWTAuth\Claims\JwtId;
use Tymon\JWTAuth\Claims\Issuer;
use Tymon\JWTAuth\Claims\Subject;
use Tymon\JWTAuth\Claims\Audience;
use Tymon\JWTAuth\Claims\IssuedAt;
use Tymon\JWTAuth\Claims\NotBefore;
use Tymon\JWTAuth\Claims\Expiration;

class PayloadTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        Carbon::setTestNow(Carbon::createFromTimeStampUTC(123));

        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration(123 + 3600),
            new NotBefore(123),
            new IssuedAt(123),
            new JwtId('foo'),
        ];

        $this->validator = Mockery::mock('Tymon\JWTAuth\Validators\PayloadValidator');
        $this->validator->shouldReceive('setRefreshFlow->check');

        $this->payload = new Payload($claims, $this->validator);
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /** @test */
    public function it_throws_an_exception_when_trying_to_add_to_the_payload()
    {
        $this->setExpectedException('Tymon\JWTAuth\Exceptions\PayloadException');

        $this->payload['foo'] = 'bar';
    }

    /** @test */
    public function it_throws_an_exception_when_trying_to_remove_a_key_from_the_payload()
    {
        $this->setExpectedException('Tymon\JWTAuth\Exceptions\PayloadException');

        unset($this->payload['foo']);
    }

    /** @test */
    public function it_should_cast_the_payload_to_a_string_as_json()
    {
        $this->assertEquals((string) $this->payload, json_encode($this->payload->get()));
        $this->assertJsonStringEqualsJsonString((string) $this->payload, json_encode($this->payload->get()));
    }

    /** @test */
    public function it_should_allow_array_access_on_the_payload()
    {
        $this->assertTrue(isset($this->payload['iat']));
        $this->assertEquals($this->payload['sub'], 1);
        $this->assertArrayHasKey('exp', $this->payload);
    }

    /** @test */
    public function it_should_get_properties_of_payload_via_get_method()
    {
        $this->assertInternalType('array', $this->payload->get());
        $this->assertEquals($this->payload->get('sub'), 1);
    }

    /** @test */
    public function it_should_get_multiple_properties_when_passing_an_array_to_the_get_method()
    {
        $values = $this->payload->get(['sub', 'jti']);

        list($sub, $jti) = $values;

        $this->assertInternalType('array', $values);
        $this->assertEquals($sub, 1);
        $this->assertEquals($jti, 'foo');
    }

    /** @test */
    public function it_should_determine_whether_the_payload_has_a_claim()
    {
        $this->assertTrue($this->payload->has(new Subject(1)));
        $this->assertFalse($this->payload->has(new Audience(1)));
    }

    /** @test */
    public function it_should_magically_get_a_property()
    {
        $sub = $this->payload->getSubject();
        $jti = $this->payload->getJwtId();
        $iss = $this->payload->getIssuer();

        $this->assertEquals($sub, 1);
        $this->assertEquals($jti, 'foo');
        $this->assertEquals($iss, 'http://example.com');
    }

    /** @test */
    public function it_should_throw_an_exception_when_magically_getting_a_property_that_does_not_exist()
    {
        $this->setExpectedException('\BadMethodCallException');

        $this->payload->getFoo();
    }

    /** @test */
    public function it_should_get_the_claims()
    {
        $claims = $this->payload->getClaims();

        $this->assertInstanceOf('Tymon\JWTAuth\Claims\Expiration', $claims[2]);
        $this->assertInstanceOf('Tymon\JWTAuth\Claims\JwtId', $claims[5]);
    }
}
