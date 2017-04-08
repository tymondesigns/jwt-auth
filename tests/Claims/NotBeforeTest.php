<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test\Claims;

use Tymon\JWTAuth\Claims\NotBefore;
use Tymon\JWTAuth\Test\AbstractTestCase;

class NotBeforeTest extends AbstractTestCase
{
    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\InvalidClaimException
     * @expectedExceptionMessage Invalid value provided for claim [nbf]
     */
    public function it_should_throw_an_exception_when_passing_a_future_timestamp()
    {
        new NotBefore($this->testNowTimestamp + 3600);
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\InvalidClaimException
     * @expectedExceptionMessage Invalid value provided for claim [nbf]
     */
    public function it_should_throw_an_exception_when_passing_an_invalid_value()
    {
        new NotBefore('foo');
    }
}
