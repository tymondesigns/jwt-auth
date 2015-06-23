<?php

namespace Tymon\JWTAuth\Test;

use Tymon\JWTAuth\Validators\TokenValidator;

class TokenValidatorTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->validator = new TokenValidator();
    }

    /** @test */
    public function it_should_return_true_when_providing_a_well_formed_token()
    {
        $this->assertTrue($this->validator->isValid('one.two.three'));
    }

    /** @test */
    public function it_should_return_false_when_providing_a_malformed_token()
    {
        $this->assertFalse($this->validator->isValid('one.two.three.four.five'));
    }

    /** @test */
    public function it_should_throw_an_axception_when_providing_a_malformed_token()
    {
        $this->setExpectedException('Tymon\JWTAuth\Exceptions\TokenInvalidException');

        $this->validator->check('one.two.three.four.five');
    }
}
