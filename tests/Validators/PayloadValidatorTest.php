<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test\Validators;

use Tymon\JWTAuth\Claims\JwtId;
use Tymon\JWTAuth\Claims\Issuer;
use Tymon\JWTAuth\Claims\Subject;
use Tymon\JWTAuth\Claims\IssuedAt;
use Tymon\JWTAuth\Claims\NotBefore;
use Tymon\JWTAuth\Claims\Collection;
use Tymon\JWTAuth\Claims\Expiration;
use Tymon\JWTAuth\Test\AbstractTestCase;
use Tymon\JWTAuth\Validators\PayloadValidator;

class PayloadValidatorTest extends AbstractTestCase
{
    /** @test */
    public function it_should_return_true_when_providing_a_valid_payload()
    {
        $claims = [
            new Subject(1),
            new Issuer('example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->assertTrue(PayloadValidator::isValid($collection));
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\TokenExpiredException
     * @expectedExceptionMessage Token has expired
     */
    public function it_should_throw_an_exception_when_providing_an_expired_payload()
    {
        $claims = [
            new Subject(1),
            new Issuer('example.com'),
            new Expiration($this->testNowTimestamp - 1440),
            new NotBefore($this->testNowTimestamp - 3660),
            new IssuedAt($this->testNowTimestamp - 3660),
            new JwtId('foo'),
        ];

        $collection = Collection::make($claims);

        PayloadValidator::check($collection);
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\InvalidClaimException
     * @expectedExceptionMessage Invalid value provided for claim [nbf]
     */
    public function it_should_throw_an_exception_when_providing_an_invalid_nbf_claim()
    {
        $claims = [
            new Subject(1),
            new Issuer('example.com'),
            new Expiration($this->testNowTimestamp + 1440),
            new NotBefore($this->testNowTimestamp + 3660),
            new IssuedAt($this->testNowTimestamp - 3660),
            new JwtId('foo'),
        ];

        $collection = Collection::make($claims);

        PayloadValidator::check($collection);
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\InvalidClaimException
     * @expectedExceptionMessage Invalid value provided for claim [iat]
     */
    public function it_should_throw_an_exception_when_providing_an_invalid_iat_claim()
    {
        $claims = [
            new Subject(1),
            new Issuer('example.com'),
            new Expiration($this->testNowTimestamp + 1440),
            new NotBefore($this->testNowTimestamp - 3660),
            new IssuedAt($this->testNowTimestamp + 3660),
            new JwtId('foo'),
        ];

        $collection = Collection::make($claims);

        PayloadValidator::check($collection);
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\TokenInvalidException
     * @expectedExceptionMessage JWT does not contain the required claims
     */
    public function it_should_throw_an_exception_when_providing_an_invalid_payload()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
        ];

        $collection = Collection::make($claims);

        PayloadValidator::check($collection, ['foo']);
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\InvalidClaimException
     * @expectedExceptionMessage Invalid value provided for claim [exp]
     */
    public function it_should_throw_an_exception_when_providing_an_invalid_expiry()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration('foo'),
            new NotBefore($this->testNowTimestamp - 3660),
            new IssuedAt($this->testNowTimestamp + 3660),
            new JwtId('foo'),
        ];

        $collection = Collection::make($claims);

        PayloadValidator::check($collection);
    }

    /** @test */
    public function it_should_set_the_required_claims()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
        ];

        $collection = Collection::make($claims);

        $this->assertTrue(PayloadValidator::isValid($collection, ['iss', 'sub']));
    }
}
