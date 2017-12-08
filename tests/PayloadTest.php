<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test;

use Mockery;
use Tymon\JWTAuth\Payload;
use Tymon\JWTAuth\Claims\Claim;
use Tymon\JWTAuth\Claims\JwtId;
use Tymon\JWTAuth\Claims\Issuer;
use Tymon\JWTAuth\Claims\Subject;
use Tymon\JWTAuth\Claims\Audience;
use Tymon\JWTAuth\Claims\IssuedAt;
use Tymon\JWTAuth\Claims\NotBefore;
use Tymon\JWTAuth\Claims\Collection;
use Tymon\JWTAuth\Claims\Expiration;
use Tymon\JWTAuth\Validators\PayloadValidator;

class PayloadTest extends AbstractTestCase
{
    /**
     * @var \Mockery\MockInterface|\Tymon\JWTAuth\Validators\PayloadValidator
     */
    protected $validator;

    /**
     * @var \Tymon\JWTAuth\Payload
     */
    protected $payload;

    public function setUp()
    {
        parent::setUp();

        $this->payload = $this->getTestPayload();
    }

    /**
     * @param  array  $extraClaims
     *
     * @return \Tymon\JWTAuth\Payload
     */
    private function getTestPayload(array $extraClaims = [])
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];

        if ($extraClaims) {
            $claims = array_merge($claims, $extraClaims);
        }

        $collection = Collection::make($claims);

        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        return new Payload($collection, $this->validator);
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\PayloadException
     * @expectedExceptionMessage The payload is immutable
     */
    public function it_should_throw_an_exception_when_trying_to_add_to_the_payload()
    {
        $this->payload['foo'] = 'bar';
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\PayloadException
     * @expectedExceptionMessage The payload is immutable
     */
    public function it_should_throw_an_exception_when_trying_to_remove_a_key_from_the_payload()
    {
        unset($this->payload['foo']);
    }

    /** @test */
    public function it_should_cast_the_payload_to_a_string_as_json()
    {
        $this->assertSame((string) $this->payload, json_encode($this->payload->get(), JSON_UNESCAPED_SLASHES));
        $this->assertJsonStringEqualsJsonString((string) $this->payload, json_encode($this->payload->get()));
    }

    /** @test */
    public function it_should_allow_array_access_on_the_payload()
    {
        $this->assertTrue(isset($this->payload['iat']));
        $this->assertSame($this->payload['sub'], 1);
        $this->assertArrayHasKey('exp', $this->payload);
    }

    /** @test */
    public function it_should_get_properties_of_payload_via_get_method()
    {
        $this->assertInternalType('array', $this->payload->get());
        $this->assertSame($this->payload->get('sub'), 1);

        $this->assertSame(
            $this->payload->get(function () {
                return 'jti';
            }),
            'foo'
        );
    }

    /** @test */
    public function it_should_get_multiple_properties_when_passing_an_array_to_the_get_method()
    {
        $values = $this->payload->get(['sub', 'jti']);

        list($sub, $jti) = $values;

        $this->assertInternalType('array', $values);
        $this->assertSame($sub, 1);
        $this->assertSame($jti, 'foo');
    }

    /** @test */
    public function it_should_determine_whether_the_payload_has_a_claim()
    {
        $this->assertTrue($this->payload->has(new Subject(1)));
        $this->assertFalse($this->payload->has(new Audience(1)));
    }

    /** @test */
    public function it_should_magically_get_a_property()
    {
        $sub = $this->payload->getSubject();
        $jti = $this->payload->getJwtId();
        $iss = $this->payload->getIssuer();

        $this->assertSame($sub, 1);
        $this->assertSame($jti, 'foo');
        $this->assertSame($iss, 'http://example.com');
    }

    /** @test */
    public function it_should_invoke_the_instance_as_a_callable()
    {
        $payload = $this->payload;

        $sub = $payload('sub');
        $jti = $payload('jti');
        $iss = $payload('iss');

        $this->assertSame($sub, 1);
        $this->assertSame($jti, 'foo');
        $this->assertSame($iss, 'http://example.com');

        $this->assertSame($payload(), $this->payload->toArray());
    }

    /**
     * @test
     * @expectedException \BadMethodCallException
     * @expectedExceptionMessage The claim [getFoo] does not exist on the payload.
     */
    public function it_should_throw_an_exception_when_magically_getting_a_property_that_does_not_exist()
    {
        $this->payload->getFoo();
    }

    /** @test */
    public function it_should_get_the_claims()
    {
        $claims = $this->payload->getClaims();

        $this->assertInstanceOf(Expiration::class, $claims['exp']);
        $this->assertInstanceOf(JwtId::class, $claims['jti']);
        $this->assertInstanceOf(Subject::class, $claims['sub']);

        $this->assertContainsOnlyInstancesOf(Claim::class, $claims);
    }

    /** @test */
    public function it_should_get_the_object_as_json()
    {
        $this->assertJsonStringEqualsJsonString(json_encode($this->payload), $this->payload->toJson());
    }

    /** @test */
    public function it_should_count_the_claims()
    {
        $this->assertSame(6, $this->payload->count());
        $this->assertCount(6, $this->payload);
    }

    /** @test */
    public function it_should_match_values()
    {
        $values = $this->payload->toArray();
        $values['sub'] = (string) $values['sub'];

        $this->assertTrue($this->payload->matches($values));
    }

    /** @test */
    public function it_should_match_strict_values()
    {
        $values = $this->payload->toArray();

        $this->assertTrue($this->payload->matchesStrict($values));
        $this->assertTrue($this->payload->matches($values, true));
    }

    /** @test */
    public function it_should_not_match_empty_values()
    {
        $this->assertFalse($this->payload->matches([]));
    }

    /** @test */
    public function it_should_not_match_values()
    {
        $values = $this->payload->toArray();
        $values['sub'] = 'dummy_subject';

        $this->assertFalse($this->payload->matches($values));
    }

    /** @test */
    public function it_should_not_match_strict_values()
    {
        $values = $this->payload->toArray();
        $values['sub'] = (string) $values['sub'];

        $this->assertFalse($this->payload->matchesStrict($values));
        $this->assertFalse($this->payload->matches($values, true));
    }

    /** @test */
    public function it_should_not_match_a_non_existing_claim()
    {
        $values = ['foo' => 'bar'];

        $this->assertFalse($this->payload->matches($values));
    }
}
