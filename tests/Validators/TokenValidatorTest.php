<?php

/*
 * This file is part of jwt-auth
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test\Validators;

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

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\TokenInvalidException
     */
    public function it_should_throw_an_axception_when_providing_a_malformed_token()
    {
        $this->validator->check('one.two.three.four.five');
    }
}
