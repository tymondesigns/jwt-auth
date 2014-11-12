<?php

namespace Tymon\JWTAuth\Test;

use Tymon\JWTAuth\Validators\PayloadValidator;

class PayloadValidatorTest extends \PHPUnit_Framework_TestCase
{

	/** @test */
	public function it_should_return_true_when_providing_a_valid_payload()
	{
		$payload = [
            'iss' => 'http://example.com',
            'iat' => time(),
            'exp' => time() + 3600,
            'sub' => 1,
            'jti' => 'foo'
        ];

		$this->assertTrue(PayloadValidator::isValid($payload));
	}

	/** @test */
	public function it_should_throw_an_exception_when_providing_an_expired_payload()
	{
		$this->setExpectedException('Tymon\JWTAuth\Exceptions\TokenExpiredException');

		$payload = [
            'iss' => 'http://example.com',
            'iat' => time() - 3660,
            'exp' => time() - 1440,
            'sub' => 1,
            'jti' => 'foo'
        ];

		PayloadValidator::check($payload);
	}

	/** @test */
	public function it_should_throw_an_exception_when_providing_an_invalid_payload()
	{
		$this->setExpectedException('Tymon\JWTAuth\Exceptions\TokenInvalidException');

		$payload = [
            'iss' => 'http://example.com',
            'sub' => 1
        ];

		PayloadValidator::check($payload);
	}

	/** @test */
	public function it_should_throw_an_exception_when_providing_an_invalid_expiry()
	{
		$this->setExpectedException('Tymon\JWTAuth\Exceptions\TokenInvalidException');

		$payload = [
            'iss' => 'http://example.com',
            'iat' => time() - 3660,
            'exp' => 'foo',
            'sub' => 1,
            'jti' => 'foo'
        ];

		PayloadValidator::check($payload);
	}
}