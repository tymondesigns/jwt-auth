<?php

namespace Tymon\JWTAuth\Test;

use Tymon\JWTAuth\Validators\TokenValidator;

class TokenValidatorTest extends \PHPUnit_Framework_TestCase
{

	/** @test */
	public function it_should_return_true_when_providing_a_well_formed_token()
	{
		$this->assertTrue(TokenValidator::isValid('one.two.three'));
	}

	/** @test */
	public function it_should_return_false_when_providing_a_malformed_token()
	{
		$this->assertFalse(TokenValidator::isValid('one.two.three.four.five'));
	}

	/** @test */
	public function it_should_throw_an_axception_when_providing_a_malformed_token()
	{
		$this->setExpectedException('Tymon\JWTAuth\Exceptions\TokenInvalidException');

		TokenValidator::check('one.two.three.four.five');
	}
}