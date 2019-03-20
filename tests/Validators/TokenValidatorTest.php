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
use Tymon\JWTAuth\Validators\TokenValidator;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class TokenValidatorTest extends AbstractTestCase
{
    /** @test */
    public function it_should_return_true_when_providing_a_well_formed_token()
    {
        $this->assertTrue(TokenValidator::isValid('one.two.three'));
    }

    /**
     * @test
     * @dataProvider \Tymon\JWTAuth\Test\Validators\TokenValidatorTest::dataProviderMalformedTokens
     *
     * @param  string  $token
     */
    public function it_should_return_false_when_providing_a_malformed_token($token)
    {
        $this->assertFalse(TokenValidator::isValid($token));
    }

    /**
     * @test
     * @dataProvider \Tymon\JWTAuth\Test\Validators\TokenValidatorTest::dataProviderMalformedTokens
     *
     * @param  string  $token
     */
    public function it_should_throw_an_exception_when_providing_a_malformed_token($token)
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Malformed token');

        TokenValidator::check($token);
    }

    public function dataProviderTokensWithWrongSegmentsNumber()
    {
        return [['one.two'], ['one.two.three.four'], ['one.two.three.four.five']];
    }

    /**
     * @test
     * @dataProvider \Tymon\JWTAuth\Test\Validators\TokenValidatorTest::dataProviderTokensWithWrongSegmentsNumber
     *
     * @param  string  $token
     */
    public function it_should_return_false_when_providing_a_token_with_wrong_segments_number(
        $token
    ) {
        $this->assertFalse(TokenValidator::isValid($token));
    }

    /**
     * @test
     * @dataProvider \Tymon\JWTAuth\Test\Validators\TokenValidatorTest::dataProviderTokensWithWrongSegmentsNumber
     *
     * @param  string  $token
     */
    public function it_should_throw_an_exception_when_providing_a_malformed_token_with_wrong_segments_number(
        $token
    ) {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Wrong number of segments');

        TokenValidator::check($token);
    }

    public function dataProviderMalformedTokens()
    {
        return [
            ['one.two.'],
            ['.two.'],
            ['.two.three'],
            ['one..three'],
            ['..'],
            [' . . '],
            [' one . two . three '],
        ];
    }
}
