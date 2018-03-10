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

use Tymon\JWTAuth\Claims\JwtId;
use Tymon\JWTAuth\Claims\Custom;
use Tymon\JWTAuth\Claims\Issuer;
use Tymon\JWTAuth\Claims\Factory;
use Tymon\JWTAuth\Claims\Subject;
use Tymon\JWTAuth\Claims\IssuedAt;
use Tymon\JWTAuth\Claims\NotBefore;
use Tymon\JWTAuth\Claims\Expiration;
use Tymon\JWTAuth\Test\Fixtures\Foo;
use Tymon\JWTAuth\Test\AbstractTestCase;

class FactoryTest extends AbstractTestCase
{
    /** @test */
    public function it_should_get_a_defined_claim_instance_when_passing_a_name_and_value()
    {
        $this->assertInstanceOf(Subject::class, Factory::get('sub', 1));
        $this->assertInstanceOf(Issuer::class, Factory::get('iss', 'http://example.com'));
        $this->assertInstanceOf(Expiration::class, Factory::get('exp', $this->testNowTimestamp + 3600));
        $this->assertInstanceOf(NotBefore::class, Factory::get('nbf', $this->testNowTimestamp));
        $this->assertInstanceOf(IssuedAt::class, Factory::get('iat', $this->testNowTimestamp));
        $this->assertInstanceOf(JwtId::class, Factory::get('jti', 'foo'));
    }

    /** @test */
    public function it_should_get_a_custom_claim_instance_when_passing_a_non_defined_name_and_value()
    {
        $this->assertInstanceOf(Custom::class, Factory::get('foo', ['bar']));
    }

    /** @test */
    public function it_should_make_a_claim_instance_for_inferred_claims()
    {
        $iat = Factory::get('iat');
        $this->assertSame($this->testNowTimestamp, $iat->getValue());
        $this->assertInstanceOf(IssuedAt::class, $iat);

        $nbf = Factory::get('nbf');
        $this->assertSame($this->testNowTimestamp, $nbf->getValue());
        $this->assertInstanceOf(NotBefore::class, $nbf);

        $jti = Factory::get('jti');
        $this->assertInstanceOf(JwtId::class, $jti);
    }
}
