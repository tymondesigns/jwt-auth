<?php

namespace spec\Tymon\JWTAuth;

use PhpSpec\ObjectBehavior;

class PayloadSpec extends ObjectBehavior
{

	function it_creates_the_object_when_passing_a_valid_payload()
	{
		$payload = [
			'iat' => time(),
			'exp' => time() + (60 * 60), // plus 1 hour
			'sub' => 1,
			'iss' => 'http://example.com',
			'custom' => 'data'
		];

		$this->beConstructedWith($payload);
		
		$this->shouldHaveType('Tymon\JWTAuth\Payload');
		
		$this->get()->shouldBe($payload);
		$this->get('custom')->shouldBe('data');
		$this['sub']->shouldBe(1);

		$this['extra'] = 'something';
		$this->get('extra')->shouldBe('something');
	}

	function it_should_throw_an_exception_when_payload_does_not_contain_required_claims()
	{
		$payload = ['iat' => 12312312, 'exp' => 13234234];

		$this->shouldThrow('Tymon\JWTAuth\Exceptions\PayloadException')->during('__construct', [$payload]);
	}

	function it_should_throw_an_exception_when_payload_has_invalid_expiration()
	{
		$payload = [
			'iat' => time(),
			'exp' => '1234567',
			'sub' => 1,
			'iss' => 'http://example.com'
		];

		$this->shouldThrow('Tymon\JWTAuth\Exceptions\PayloadException')->during('__construct', [$payload]);
	}

	function it_should_throw_an_exception_when_payload_has_expired()
	{
		$payload = [
			'iat' => time() - (120 * 60),
			'exp' => time() - (60 * 60), // minus 1 hour
			'sub' => 1,
			'iss' => 'http://example.com',
		];

		$this->shouldThrow('Tymon\JWTAuth\Exceptions\PayloadException')->during('__construct', [$payload]);
	}

}
