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

    public function setUp(): void
    {
        parent::setUp();

        $this->claimsTimestamp = [
            Subject::NAME => new Subject(1),
            Issuer::NAME => new Issuer('http://example.com'),
            Expiration::NAME => new Expiration($this->testNowTimestamp + 3600),
            NotBefore::NAME => new NotBefore($this->testNowTimestamp),
            IssuedAt::NAME => new IssuedAt($this->testNowTimestamp),
            JwtId::NAME => new JwtId('foo'),
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
            Subject::NAME => new Subject(1),
            Issuer::NAME => new Issuer('http://example.com'),
            Expiration::NAME => new Expiration($testCarbonCopy->addHour()),
            NotBefore::NAME => new NotBefore($testCarbon),
            IssuedAt::NAME => new IssuedAt($testCarbon),
            JwtId::NAME => new JwtId('foo'),
        ];

        $payloadTimestamp = new Payload(Collection::make($this->claimsTimestamp));
        $payloadDatetime = new Payload(Collection::make($claimsDatetime));

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
            Subject::NAME => new Subject(1),
            Issuer::NAME => new Issuer('http://example.com'),
            Expiration::NAME => new Expiration($testDateTimeCopy->modify('+3600 seconds')),
            NotBefore::NAME => new NotBefore($testDateTime),
            IssuedAt::NAME => new IssuedAt($testDateTime),
            JwtId::NAME => new JwtId('foo'),
        ];

        $payloadTimestamp = new Payload(Collection::make($this->claimsTimestamp));
        $payloadDatetime = new Payload(Collection::make($claimsDatetime));

        $this->assertEquals($payloadTimestamp, $payloadDatetime);
    }

    /** @test */
    public function it_should_handle_datetime_immutable_claims()
    {
        $testDateTimeImmutable = DateTimeImmutable::createFromFormat(
            'U',
            (string) $this->testNowTimestamp
        );

        $this->assertInstanceOf(DateTimeImmutable::class, $testDateTimeImmutable);
        $this->assertInstanceOf(DatetimeInterface::class, $testDateTimeImmutable);

        $claimsDatetime = [
            Subject::NAME => new Subject(1),
            Issuer::NAME => new Issuer('http://example.com'),
            Expiration::NAME => new Expiration($testDateTimeImmutable->modify('+3600 seconds')),
            NotBefore::NAME => new NotBefore($testDateTimeImmutable),
            IssuedAt::NAME => new IssuedAt($testDateTimeImmutable),
            JwtId::NAME => new JwtId('foo'),
        ];

        $payloadTimestamp = new Payload(Collection::make($this->claimsTimestamp));
        $payloadDatetime = new Payload(Collection::make($claimsDatetime));

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
            Subject::NAME => new Subject(1),
            Issuer::NAME => new Issuer('http://example.com'),
            Expiration::NAME => new Expiration($testDateInterval),
            NotBefore::NAME => new NotBefore($this->testNowTimestamp),
            IssuedAt::NAME => new IssuedAt($this->testNowTimestamp),
            JwtId::NAME => new JwtId('foo'),
        ];

        $claimsCarbonInterval = [
            Subject::NAME => new Subject(1),
            Issuer::NAME => new Issuer('http://example.com'),
            Expiration::NAME => new Expiration($carbonDateInterval),
            NotBefore::NAME => new NotBefore($this->testNowTimestamp),
            IssuedAt::NAME => new IssuedAt($this->testNowTimestamp),
            JwtId::NAME => new JwtId('foo'),
        ];

        $payloadTimestamp = new Payload(Collection::make($this->claimsTimestamp));

        $payloadDateInterval = new Payload(Collection::make($claimsDateInterval));
        $payloadClaimInterval = new Payload(Collection::make($claimsCarbonInterval));

        $this->assertEquals($payloadTimestamp, $payloadDateInterval);
        $this->assertEquals($payloadTimestamp, $payloadClaimInterval);
    }

    /** @test */
    public function it_should_get_the_date_interval_instance()
    {
        // TODO: fix this carbon issue
        $exp = new Expiration($this->testNowTimestamp + ($seconds = 3600));
        // $this->assertEquals(CarbonInterval::seconds($seconds)->cascade(), $exp->asCarbonInterval());
        // $this->assertEquals('PT1H', $exp->asCarbonInterval()->spec());

        $iat = new IssuedAt($this->testNowTimestamp);
        // $this->assertEquals(CarbonInterval::seconds(0)->cascade(), $iat->asCarbonInterval());
        // $this->assertEquals('PT0S', $iat->asCarbonInterval()->spec());
    }
}
