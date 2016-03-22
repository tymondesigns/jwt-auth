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

use Tymon\JWTAuth\Test\AbstractTestCase;
use Tymon\JWTAuth\Validators\PayloadValidator;

class PayloadValidatorTest extends AbstractTestCase
{
    /**
     * @var \Tymon\JWTAuth\Validators\PayloadValidator
     */
    protected $validator;

    public function setUp()
    {
        parent::setUp();

        $this->validator = new PayloadValidator();
    }

    /** @test */
    public function it_should_return_true_when_providing_a_valid_payload()
    {
        $payload = [
            'iss' => 'http://example.com',
            'iat' => $this->testNowTimestamp,
            'nbf' => $this->testNowTimestamp,
            'exp' => $this->testNowTimestamp + 3600,
            'sub' => 1,
            'jti' => 'foo',
        ];

        $this->assertTrue($this->validator->isValid($payload));
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\TokenExpiredException
     */
    public function it_should_throw_an_exception_when_providing_an_expired_payload()
    {
        $payload = [
            'iss' => 'http://example.com',
            'iat' => $this->testNowTimestamp - 3660,
            'nbf' => $this->testNowTimestamp - 3660,
            'exp' => $this->testNowTimestamp - 1440,
            'sub' => 1,
            'jti' => 'foo',
        ];

        $this->validator->check($payload);
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\TokenInvalidException
     */
    public function it_should_throw_an_exception_when_providing_an_invalid_nbf_claim()
    {
        $payload = [
            'iss' => 'http://example.com',
            'iat' => $this->testNowTimestamp - 3660,
            'nbf' => $this->testNowTimestamp + 3660,
            'exp' => $this->testNowTimestamp + 1440,
            'sub' => 1,
            'jti' => 'foo',
        ];

        $this->validator->check($payload);
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\TokenInvalidException
     */
    public function it_should_throw_an_exception_when_providing_an_invalid_iat_claim()
    {
        $payload = [
            'iss' => 'http://example.com',
            'iat' => $this->testNowTimestamp + 3660,
            'nbf' => $this->testNowTimestamp - 3660,
            'exp' => $this->testNowTimestamp + 1440,
            'sub' => 1,
            'jti' => 'foo',
        ];

        $this->validator->check($payload);
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\TokenInvalidException
     */
    public function it_should_throw_an_exception_when_providing_an_invalid_payload()
    {
        $payload = [
            'iss' => 'http://example.com',
            'sub' => 1,
        ];

        $this->validator->check($payload);
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\TokenInvalidException
     */
    public function it_should_throw_an_exception_when_providing_an_invalid_expiry()
    {
        $payload = [
            'iss' => 'http://example.com',
            'iat' => $this->testNowTimestamp - 3660,
            'exp' => 'foo',
            'sub' => 1,
            'jti' => 'foo',
        ];

        $this->validator->check($payload);
    }

    /** @test */
    public function it_should_set_the_required_claims()
    {
        $payload = [
            'iss' => 'http://example.com',
            'sub' => 1,
        ];

        $this->assertTrue($this->validator->setRequiredClaims(['iss', 'sub'])->isValid($payload));
    }

    /** @test */
    public function it_should_check_the_token_in_the_refresh_context()
    {
        $payload = [
            'iss' => 'http://example.com',
            'iat' => $this->testNowTimestamp - 2600, // this is LESS than the refresh ttl at 1 hour
            'nbf' => $this->testNowTimestamp,
            'exp' => $this->testNowTimestamp - 1000,
            'sub' => 1,
            'jti' => 'foo',
        ];

        $this->assertTrue(
            $this->validator->setRefreshFlow()->setRefreshTTL(60)->isValid($payload)
        );
    }

    /** @test */
    public function it_should_return_true_if_the_refresh_ttl_is_null()
    {
        $payload = [
            'iss' => 'http://example.com',
            'iat' => $this->testNowTimestamp - 2600,
            'nbf' => $this->testNowTimestamp,
            'exp' => $this->testNowTimestamp - 1000,
            'sub' => 1,
            'jti' => 'foo',
        ];

        $this->assertTrue(
            $this->validator->setRefreshFlow()->setRefreshTTL(null)->isValid($payload)
        );
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\TokenExpiredException
     */
    public function it_should_throw_an_exception_if_the_token_cannot_be_refreshed()
    {
        $payload = [
            'iss' => 'http://example.com',
            'iat' => $this->testNowTimestamp - 5000, // this is MORE than the refresh ttl at 1 hour, so is invalid
            'nbf' => $this->testNowTimestamp,
            'exp' => $this->testNowTimestamp,
            'sub' => 1,
            'jti' => 'foo',
        ];

        $this->validator->setRefreshFlow()->setRefreshTTL(60)->check($payload);
    }
}
