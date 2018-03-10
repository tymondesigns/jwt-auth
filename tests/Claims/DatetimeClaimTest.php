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

use Mockery;
use DateTime;
use DateInterval;
use Carbon\Carbon;
use DateTimeImmutable;
use DateTimeInterface;
use Carbon\CarbonInterval;
use Tymon\JWTAuth\Payload;
use Tymon\JWTAuth\Claims\JwtId;
use Tymon\JWTAuth\Claims\Issuer;
use Tymon\JWTAuth\Claims\Subject;
use Tymon\JWTAuth\Claims\IssuedAt;
use Tymon\JWTAuth\Claims\NotBefore;
use Tymon\JWTAuth\Claims\Collection;
use Tymon\JWTAuth\Claims\Expiration;
use Tymon\JWTAuth\Test\AbstractTestCase;
use Tymon\JWTAuth\Validators\PayloadValidator;

class DatetimeClaimTest extends AbstractTestCase
{
    /**
     * @var \Mockery\MockInterface|\Tymon\JWTAuth\Validators\PayloadValidator
     */
    protected $validator;

    /**
     * @var array
     */
    protected $claimsTimestamp;

    public function setUp()
    {
        parent::setUp();

        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->validator->shouldReceive('setRefreshFlow->check');

        $this->claimsTimestamp = [
            'sub' => new Subject(1),
            'iss' => new Issuer('http://example.com'),
            'exp' => new Expiration($this->testNowTimestamp + 3600),
            'nbf' => new NotBefore($this->testNowTimestamp),
            'iat' => new IssuedAt($this->testNowTimestamp),
            'jti' => new JwtId('foo'),
        ];
    }

    /** @test */
    public function it_should_handle_carbon_claims()
    {
        $testCarbon = Carbon::createFromTimestampUTC($this->testNowTimestamp);
        $testCarbonCopy = clone $testCarbon;

        $this->assertInstanceOf(Carbon::class, $testCarbon);
        $this->assertInstanceOf(Datetime::class, $testCarbon);
        $this->assertInstanceOf(DatetimeInterface::class, $testCarbon);

        $claimsDatetime = [
            'sub' => new Subject(1),
            'iss' => new Issuer('http://example.com'),
            'exp' => new Expiration($testCarbonCopy->addHour()),
            'nbf' => new NotBefore($testCarbon),
            'iat' => new IssuedAt($testCarbon),
            'jti' => new JwtId('foo'),
        ];

        $payloadTimestamp = new Payload(Collection::make($this->claimsTimestamp), $this->validator);
        $payloadDatetime = new Payload(Collection::make($claimsDatetime), $this->validator);

        $this->assertEquals($payloadTimestamp, $payloadDatetime);
    }

    /** @test */
    public function it_should_handle_datetime_claims()
    {
        $testDateTime = DateTime::createFromFormat('U', $this->testNowTimestamp);
        $testDateTimeCopy = clone $testDateTime;

        $this->assertInstanceOf(DateTime::class, $testDateTime);
        $this->assertInstanceOf(DatetimeInterface::class, $testDateTime);

        $claimsDatetime = [
            'sub' => new Subject(1),
            'iss' => new Issuer('http://example.com'),
            'exp' => new Expiration($testDateTimeCopy->modify('+3600 seconds')),
            'nbf' => new NotBefore($testDateTime),
            'iat' => new IssuedAt($testDateTime),
            'jti' => new JwtId('foo'),
        ];

        $payloadTimestamp = new Payload(Collection::make($this->claimsTimestamp), $this->validator);
        $payloadDatetime = new Payload(Collection::make($claimsDatetime), $this->validator);

        $this->assertEquals($payloadTimestamp, $payloadDatetime);
    }

    /** @test */
    public function it_should_handle_datetime_immutable_claims()
    {
        $testDateTimeImmutable = DateTimeImmutable::createFromFormat('U', (string) $this->testNowTimestamp);

        $this->assertInstanceOf(DateTimeImmutable::class, $testDateTimeImmutable);
        $this->assertInstanceOf(DatetimeInterface::class, $testDateTimeImmutable);

        $claimsDatetime = [
            'sub' => new Subject(1),
            'iss' => new Issuer('http://example.com'),
            'exp' => new Expiration($testDateTimeImmutable->modify('+3600 seconds')),
            'nbf' => new NotBefore($testDateTimeImmutable),
            'iat' => new IssuedAt($testDateTimeImmutable),
            'jti' => new JwtId('foo'),
        ];

        $payloadTimestamp = new Payload(Collection::make($this->claimsTimestamp), $this->validator);
        $payloadDatetime = new Payload(Collection::make($claimsDatetime), $this->validator);

        $this->assertEquals($payloadTimestamp, $payloadDatetime);
    }

    /** @test */
    public function it_should_handle_datetinterval_claims()
    {
        $testDateInterval = new DateInterval('PT1H');
        $carbonDateInterval = CarbonInterval::hours(1);

        $this->assertInstanceOf(DateInterval::class, $testDateInterval);
        $this->assertInstanceOf(DateInterval::class, $carbonDateInterval);

        $claimsDateInterval = [
            'sub' => new Subject(1),
            'iss' => new Issuer('http://example.com'),
            'exp' => new Expiration($testDateInterval),
            'nbf' => new NotBefore($this->testNowTimestamp),
            'iat' => new IssuedAt($this->testNowTimestamp),
            'jti' => new JwtId('foo'),
        ];

        $claimsCarbonInterval = [
            'sub' => new Subject(1),
            'iss' => new Issuer('http://example.com'),
            'exp' => new Expiration($carbonDateInterval),
            'nbf' => new NotBefore($this->testNowTimestamp),
            'iat' => new IssuedAt($this->testNowTimestamp),
            'jti' => new JwtId('foo'),
        ];

        $payloadTimestamp = new Payload(Collection::make($this->claimsTimestamp));

        $payloadDateInterval = new Payload(Collection::make($claimsDateInterval));
        $payloadClaimInterval = new Payload(Collection::make($claimsCarbonInterval));

        $this->assertEquals($payloadTimestamp, $payloadDateInterval);
        $this->assertEquals($payloadTimestamp, $payloadClaimInterval);
    }
}
