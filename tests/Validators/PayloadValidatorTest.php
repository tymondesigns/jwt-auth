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

use Carbon\Carbon;
use Tymon\JWTAuth\Validators\PayloadValidator;

class PayloadValidatorTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        Carbon::setTestNow(Carbon::createFromTimeStampUTC(123));
        $this->validator = new PayloadValidator();
    }

    /** @test */
    public function it_should_return_true_when_providing_a_valid_payload()
    {
        $payload = [
            'iss' => 'http://example.com',
            'iat' => 100,
            'nbf' => 100,
            'exp' => 100 + 3600,
            'sub' => 1,
            'jti' => 'foo',
        ];

        $this->assertTrue($this->validator->isValid($payload));
    }

    /** @test */
    public function it_should_throw_an_exception_when_providing_an_expired_payload()
    {
        $this->setExpectedException('Tymon\JWTAuth\Exceptions\TokenExpiredException');

        $payload = [
            'iss' => 'http://example.com',
            'iat' => 20,
            'nbf' => 20,
            'exp' => 120,
            'sub' => 1,
            'jti' => 'foo',
        ];

        $this->validator->check($payload);
    }

    /** @test */
    public function it_should_throw_an_exception_when_providing_an_invalid_nbf_claim()
    {
        $this->setExpectedException('Tymon\JWTAuth\Exceptions\TokenInvalidException');

        $payload = [
            'iss' => 'http://example.com',
            'iat' => 100,
            'nbf' => 150,
            'exp' => 150 + 3600,
            'sub' => 1,
            'jti' => 'foo',
        ];

        $this->validator->check($payload);
    }

    /** @test */
    public function it_should_throw_an_exception_when_providing_an_invalid_iat_claim()
    {
        $this->setExpectedException('Tymon\JWTAuth\Exceptions\TokenInvalidException');

        $payload = [
            'iss' => 'http://example.com',
            'iat' => 150,
            'nbf' => 100,
            'exp' => 150 + 3600,
            'sub' => 1,
            'jti' => 'foo',
        ];

        $this->validator->check($payload);
    }

    /** @test */
    public function it_should_throw_an_exception_when_providing_an_invalid_payload()
    {
        $this->setExpectedException('Tymon\JWTAuth\Exceptions\TokenInvalidException');

        $payload = [
            'iss' => 'http://example.com',
            'sub' => 1,
        ];

        $this->validator->check($payload);
    }

    /** @test */
    public function it_should_throw_an_exception_when_providing_an_invalid_expiry()
    {
        $this->setExpectedException('Tymon\JWTAuth\Exceptions\TokenInvalidException');

        $payload = [
            'iss' => 'http://example.com',
            'iat' => 100,
            'exp' => 'foo',
            'sub' => 1,
            'jti' => 'foo',
        ];

        $this->validator->check($payload);
    }
}
