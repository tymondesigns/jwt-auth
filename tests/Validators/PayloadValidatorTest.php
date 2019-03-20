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

use Tymon\JWTAuth\Options;
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
     */
    public function it_should_throw_an_exception_when_providing_an_expired_payload()
    {
        $this->setExpectedException(\Tymon\JWTAuth\Exceptions\TokenExpiredException::class, 'Token has expired');

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
     */
    public function it_should_throw_an_exception_when_providing_an_invalid_nbf_claim()
    {
        $this->setExpectedException(\Tymon\JWTAuth\Exceptions\TokenInvalidException::class, 'Not Before (nbf) timestamp cannot be in the future');

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
     */
    public function it_should_throw_an_exception_when_providing_an_invalid_iat_claim()
    {
        $this->setExpectedException(\Tymon\JWTAuth\Exceptions\InvalidClaimException::class, 'Invalid value provided for claim [iat]');

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
     */
    public function it_should_throw_an_exception_when_providing_an_invalid_payload()
    {
        $this->setExpectedException(\Tymon\JWTAuth\Exceptions\TokenInvalidException::class, 'JWT does not contain the required claims');

        $claims = [new Subject(1), new Issuer('http://example.com')];

        $collection = Collection::make($claims);

        PayloadValidator::check($collection, new Options(['required_claims' => ['foo']]));
    }

    /**
     * @test
     */
    public function it_should_throw_an_exception_when_providing_an_invalid_expiry()
    {
        $this->setExpectedException(\Tymon\JWTAuth\Exceptions\InvalidClaimException::class, 'Invalid value provided for claim [exp]');

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
        $claims = [new Subject(1), new Issuer('http://example.com')];

        $collection = Collection::make($claims);

        $this->assertTrue(
            PayloadValidator::isValid($collection, new Options([
                'required_claims' => [Issuer::NAME, Subject::NAME],
            ]))
        );
    }
}
