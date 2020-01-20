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

use Tymon\JWTAuth\Claims\Collection;
use Tymon\JWTAuth\Claims\Expiration;
use Tymon\JWTAuth\Claims\IssuedAt;
use Tymon\JWTAuth\Claims\Issuer;
use Tymon\JWTAuth\Claims\JwtId;
use Tymon\JWTAuth\Claims\NotBefore;
use Tymon\JWTAuth\Claims\Subject;
use Tymon\JWTAuth\Test\AbstractTestCase;

class CollectionTest extends AbstractTestCase
{
    /** @test */
    public function it_should_sanitize_the_claims_to_associative_array()
    {
        $collection = $this->getCollection();

        $this->assertSame(array_keys($collection->toArray()), [
            Subject::NAME,
            Issuer::NAME,
            Expiration::NAME,
            NotBefore::NAME,
            IssuedAt::NAME,
            JwtId::NAME,
        ]);
    }

    /** @test */
    public function it_should_determine_if_a_collection_contains_all_the_given_claims()
    {
        $collection = $this->getCollection();

        $this->assertFalse(
            $collection->hasAllClaims([Subject::NAME, Issuer::NAME, Expiration::NAME, NotBefore::NAME, IssuedAt::NAME, JwtId::NAME, 'abc'])
        );
        $this->assertFalse($collection->hasAllClaims(['foo', 'bar']));

        $this->assertTrue($collection->hasAllClaims([]));
        $this->assertTrue($collection->hasAllClaims([Subject::NAME, Issuer::NAME]));
        $this->assertTrue($collection->hasAllClaims([Subject::NAME, Issuer::NAME, Expiration::NAME, NotBefore::NAME, IssuedAt::NAME, JwtId::NAME]));
    }

    /** @test */
    public function it_should_get_a_claim_instance_by_name()
    {
        $collection = $this->getCollection();

        $this->assertInstanceOf(Expiration::class, $collection->getByClaimName(Expiration::NAME));
        $this->assertInstanceOf(Subject::class, $collection->getByClaimName(Subject::NAME));
        $this->assertInstanceOf(Issuer::class, $collection->getByClaimName(Issuer::NAME));
        $this->assertInstanceOf(JwtId::class, $collection->getByClaimName(JwtId::NAME));
    }

    private function getCollection()
    {
        return new Collection([
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ]);
    }
}
