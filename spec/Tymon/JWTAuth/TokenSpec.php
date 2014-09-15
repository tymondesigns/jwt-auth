<?php

namespace spec\Tymon\JWTAuth;

use PhpSpec\ObjectBehavior;

class TokenSpec extends ObjectBehavior {

	function it_creates_the_object_when_passing_a_well_formed_token()
	{
		$token = '32faewfasrf4.asrgfdrgaergq34.aergae4g34gq43g';

		$this->beConstructedWith($token);
		$this->shouldHaveType('Tymon\JWTAuth\Token');

		$this->get()->shouldBe($token);
	}

	function it_should_throw_an_exception_when_a_malformed_token_is_passed()
	{
		$token = '32faewfa.srf4.asrgfdr.gaergq34.aergae4g34gq.43g';

		$this->shouldThrow('Tymon\JWTAuth\Exceptions\JWTException')->during('__construct', [$token]);
	}

}
