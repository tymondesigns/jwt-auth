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

use Tymon\JWTAuth\Factory;
use Tymon\JWTAuth\Payload;
use Tymon\JWTAuth\Claims\JwtId;
use Tymon\JWTAuth\Claims\Custom;
use Tymon\JWTAuth\Claims\Issuer;
use Tymon\JWTAuth\Claims\Subject;
use Tymon\JWTAuth\Claims\IssuedAt;
use Tymon\JWTAuth\Claims\NotBefore;

class FactoryTest extends AbstractTestCase
{
    /** @test */
    public function it_should_return_a_payload_when_passing_an_array_of_claims()
    {
        $payload = Factory::make([
            'jti', // auto generated
            'iat', // auto generated
            'nbf', // auto generated
            'sub' => 1,
            'foo' => 'bar',
        ]);

        $this->assertSame($payload->get('sub'), 1);
        $this->assertSame($payload('iat'), $this->testNowTimestamp);
        $this->assertSame($payload('nbf'), $this->testNowTimestamp);
        $this->assertSame($payload['foo'], 'bar');

        $this->assertInstanceOf(Payload::class, $payload);
        $this->assertInstanceOf(Subject::class, $payload->getInternal('sub'));
        $this->assertInstanceOf(IssuedAt::class, $payload->getInternal('iat'));
        $this->assertInstanceOf(JwtId::class, $payload->getInternal('jti'));
        $this->assertInstanceOf(NotBefore::class, $payload->getInternal('nbf'));
        $this->assertInstanceOf(Custom::class, $payload->getInternal('foo'));
    }

    /** @test */
    public function it_should_return_a_payload_when_passing_an_array_of_claims_with_values()
    {
        $payload = Factory::make([
            'jti' => 'foo',
            'iat' => $this->testNowTimestamp - 3600,
            'iss' => 'example.com',
            'sub' => 1,
            'foo' => 'bar',
        ]);

        $this->assertSame($payload->get('sub'), 1);
        $this->assertSame($payload->get('jti'), 'foo');
        $this->assertSame($payload('iat'), $this->testNowTimestamp - 3600);
        $this->assertSame($payload['foo'], 'bar');
        $this->assertSame($payload['iss'], 'example.com');

        $this->assertInstanceOf(Payload::class, $payload);
        $this->assertInstanceOf(Subject::class, $payload->getInternal('sub'));
        $this->assertInstanceOf(IssuedAt::class, $payload->getInternal('iat'));
        $this->assertInstanceOf(JwtId::class, $payload->getInternal('jti'));
        $this->assertInstanceOf(Issuer::class, $payload->getInternal('iss'));
        $this->assertInstanceOf(Custom::class, $payload->getInternal('foo'));
    }
}
