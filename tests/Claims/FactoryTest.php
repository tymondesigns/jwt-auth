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

use Tymon\JWTAuth\Options;
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
        $this->assertInstanceOf(Subject::class, Factory::get(Subject::NAME, 1));
        $this->assertInstanceOf(Issuer::class, Factory::get(Issuer::NAME, 'http://example.com'));
        $this->assertInstanceOf(
            Expiration::class,
            Factory::get(Expiration::NAME, $this->testNowTimestamp + 3600)
        );
        $this->assertInstanceOf(NotBefore::class, Factory::get(NotBefore::NAME, $this->testNowTimestamp));
        $this->assertInstanceOf(IssuedAt::class, Factory::get(IssuedAt::NAME, $this->testNowTimestamp));
        $this->assertInstanceOf(JwtId::class, Factory::get(JwtId::NAME, 'foo'));
    }

    /** @test */
    public function it_should_get_a_custom_claim_instance_when_passing_a_non_defined_name_and_value()
    {
        $this->assertInstanceOf(Custom::class, Factory::get('foo', ['bar']));
    }

    /** @test */
    public function it_should_make_a_claim_instance_for_inferred_claims()
    {
        $iat = Factory::get(IssuedAt::NAME, null, new Options([
            'leeway' => 10,
            'max_refresh_period' => 2,
        ]));
        $this->assertSame($this->testNowTimestamp, $iat->getValue());
        $this->assertInstanceOf(IssuedAt::class, $iat);
        $this->assertEquals($iat->getLeeway(), 10);
        $this->assertEquals($iat->getMaxRefreshPeriod(), 2);

        $nbf = Factory::get(NotBefore::NAME, null, new Options([
            'leeway' => 20,
            'max_refresh_period' => 1,
        ]));
        $this->assertSame($this->testNowTimestamp, $nbf->getValue());
        $this->assertInstanceOf(NotBefore::class, $nbf);
        $this->assertEquals($nbf->getLeeway(), 20);
        $this->assertEquals($nbf->getMaxRefreshPeriod(), 1);

        $this->assertInstanceOf(JwtId::class, Factory::get(JwtId::NAME));
    }
}
