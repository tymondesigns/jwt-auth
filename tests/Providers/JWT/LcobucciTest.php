<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test\Providers\JWT;

use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Providers\JWT\Lcobucci;
use Tymon\JWTAuth\Providers\JWT\Provider;
use Tymon\JWTAuth\Test\AbstractTestCase;

class LcobucciTest extends AbstractTestCase
{
    /** @test */
    public function it_can_encode_claims_using_a_symmetric_key()
    {
        $payload = [
            'sub' => 1,
            'exp' => $exp = $this->testNowTimestamp + 3600,
            'iat' => $iat = $this->testNowTimestamp,
            'iss' => '/foo',
            'custom_claim' => 'foobar',
        ];

        $token = $this->getProvider('secret', Provider::ALGO_HS256)->encode($payload);
        [$header, $payload, $signature] = explode('.', $token);

        $claims = json_decode(base64_decode($payload), true);
        $headerValues = json_decode(base64_decode($header), true);

        $this->assertEquals(Provider::ALGO_HS256, $headerValues['alg']);
        $this->assertIsString($signature);

        $this->assertEquals('1', $claims['sub']);
        $this->assertEquals('/foo', $claims['iss']);
        $this->assertEquals('foobar', $claims['custom_claim']);
        $this->assertEquals($exp, $claims['exp']);
        $this->assertEquals($iat, $claims['iat']);
    }

    /** @test */
    public function it_can_encode_and_decode_a_token_using_a_symmetric_key()
    {
        $payload = [
            'sub' => 1,
            'exp' => $exp = $this->testNowTimestamp + 3600,
            'iat' => $iat = $this->testNowTimestamp,
            'iss' => '/foo',
            'custom_claim' => 'foobar',
        ];

        $provider = $this->getProvider('secret', Provider::ALGO_HS256);

        $token = $provider->encode($payload);
        $claims = $provider->decode($token);

        $this->assertEquals('1', $claims['sub']);
        $this->assertEquals('/foo', $claims['iss']);
        $this->assertEquals('foobar', $claims['custom_claim']);
        $this->assertEquals($exp, $claims['exp']);
        $this->assertEquals($iat, $claims['iat']);
    }

    /** @test */
    public function it_can_encode_and_decode_a_token_using_an_asymmetric_RS256_key()
    {
        $payload = [
            'sub' => 1,
            'exp' => $exp = $this->testNowTimestamp + 3600,
            'iat' => $iat = $this->testNowTimestamp,
            'iss' => '/foo',
            'custom_claim' => 'foobar',
        ];

        $provider = $this->getProvider(
            'secret',
            Provider::ALGO_RS256,
            ['private' => $this->getDummyPrivateKey(), 'public' => $this->getDummyPublicKey()]
        );

        $token = $provider->encode($payload);

        $header = json_decode(base64_decode(head(explode('.', $token))), true);
        $this->assertEquals(Provider::ALGO_RS256, $header['alg']);

        $claims = $provider->decode($token);

        $this->assertEquals('1', $claims['sub']);
        $this->assertEquals('/foo', $claims['iss']);
        $this->assertEquals('foobar', $claims['custom_claim']);
        $this->assertEquals($exp, $claims['exp']);
        $this->assertEquals($iat, $claims['iat']);
    }

    /** @test */
    public function it_should_throw_an_invalid_exception_when_the_payload_could_not_be_encoded()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('Could not create token:');

        $payload = [
            'sub' => 1,
            'exp' => $this->testNowTimestamp + 3600,
            'iat' => $this->testNowTimestamp,
            'iss' => '/foo',
            'custom_claim' => 'foobar',
            'invalid_utf8' => "\xB1\x31", // cannot be encoded as JSON
        ];

        $this->getProvider('secret', Provider::ALGO_HS256)->encode($payload);
    }

    /** @test */
    public function it_should_throw_a_token_invalid_exception_when_the_token_could_not_be_decoded_due_to_a_bad_signature()
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Token Signature could not be verified.');

        // This has a different secret than the one used to encode the token
        $this->getProvider('secret', Provider::ALGO_HS256)
            ->decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwiZXhwIjoxNjQ5MjYxMDY1LCJpYXQiOjE2NDkyNTc0NjUsImlzcyI6Ii9mb28iLCJjdXN0b21fY2xhaW0iOiJmb29iYXIifQ.jZufNqDHAxtboUIPmDp4ZFOIQxK-B5G6vNdBEp-9uL8');
    }

    /** @test */
    public function it_should_throw_a_token_invalid_exception_when_the_token_could_not_be_decoded_due_to_tampered_token()
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Token Signature could not be verified.');

        // This sub claim for this token has been tampered with so the signature will not match
        $this->getProvider('secret', Provider::ALGO_HS256)
            ->decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIyIiwiZXhwIjoxNjQ5MjY0OTA2LCJpYXQiOjE2NDkyNjEzMDYsImlzcyI6Ii9mb28iLCJjdXN0b21fY2xhaW0iOiJmb29iYXIifQ.IcJvMvwMXf8oEpnz8-hvAy60QDE_o8XFaxhbZIGVy0U');
    }

    /** @test */
    public function it_should_throw_a_token_invalid_exception_when_the_token_could_not_be_decoded()
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Could not decode token:');

        $this->getProvider('secret', Provider::ALGO_HS256)->decode('foo.bar.baz');
    }

    /** @test */
    public function it_should_throw_an_exception_when_the_algorithm_passed_is_invalid()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('The given algorithm could not be found');

        $this->getProvider('secret', 'INVALID_ALGO')->decode('foo.bar.baz');
    }

    /** @test */
    public function it_should_throw_an_exception_when_no_symmetric_key_is_provided_when_encoding()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('Secret is not set.');

        $this->getProvider(null, Provider::ALGO_HS256)->encode(['sub' => 1]);
    }

    /** @test */
    public function it_should_throw_an_exception_when_no_symmetric_key_is_provided_when_decoding()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('Secret is not set.');

        $this->getProvider(null, Provider::ALGO_HS256)->decode('foo.bar.baz');
    }

    /** @test */
    public function it_should_throw_an_exception_when_no_asymmetric_public_key_is_provided()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('Public key is not set.');

        $this->getProvider(
            'does_not_matter',
            Provider::ALGO_RS256,
            ['private' => $this->getDummyPrivateKey(), 'public' => null]
        )->decode('foo.bar.baz');
    }

    /** @test */
    public function it_should_throw_an_exception_when_no_asymmetric_private_key_is_provided()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('Private key is not set.');

        $this->getProvider(
            'does_not_matter',
            Provider::ALGO_RS256,
            ['private' => null, 'public' => $this->getDummyPublicKey()]
        )->encode(['sub' => 1]);
    }

    /** @test */
    public function it_should_return_the_public_key()
    {
        $provider = $this->getProvider(
            'does_not_matter',
            Provider::ALGO_RS256,
            $keys = ['private' => $this->getDummyPrivateKey(), 'public' => $this->getDummyPublicKey()]
        );

        $this->assertSame($keys['public'], $provider->getPublicKey());
    }

    /** @test */
    public function it_should_return_the_keys()
    {
        $provider = $this->getProvider(
            'does_not_matter',
            Provider::ALGO_RS256,
            $keys = ['private' => $this->getDummyPrivateKey(), 'public' => $this->getDummyPublicKey()]
        );

        $this->assertSame($keys, $provider->getKeys());
    }

    public function getProvider($secret, $algo, array $keys = [])
    {
        return new Lcobucci($secret, $algo, $keys);
    }

    public function getDummyPrivateKey()
    {
        return file_get_contents(__DIR__.'/../Keys/id_rsa');
    }

    public function getDummyPublicKey()
    {
        return file_get_contents(__DIR__.'/../Keys/id_rsa.pub');
    }
}
