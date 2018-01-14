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

use Mockery;
use Exception;
use Namshi\JOSE\JWS;
use InvalidArgumentException;
use Tymon\JWTAuth\Providers\JWT\Namshi;
use Tymon\JWTAuth\Test\AbstractTestCase;

class NamshiTest extends AbstractTestCase
{
    /**
     * @var \Mockery\MockInterface
     */
    protected $jws;

    /**
     * @var \Tymon\JWTAuth\Providers\JWT\Namshi
     */
    protected $provider;

    public function setUp()
    {
        parent::setUp();

        $this->jws = Mockery::mock(JWS::class);
    }

    /** @test */
    public function it_should_return_the_token_when_passing_a_valid_payload_to_encode()
    {
        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $this->jws->shouldReceive('setPayload')->once()->with($payload)->andReturn(Mockery::self());
        $this->jws->shouldReceive('sign')->once()->with('secret', null)->andReturn(Mockery::self());
        $this->jws->shouldReceive('getTokenString')->once()->andReturn('foo.bar.baz');

        $token = $this->getProvider('secret', 'HS256')->encode($payload);

        $this->assertSame('foo.bar.baz', $token);
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\JWTException
     * @expectedExceptionMessage Could not create token:
     */
    public function it_should_throw_an_invalid_exception_when_the_payload_could_not_be_encoded()
    {
        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $this->jws->shouldReceive('setPayload')->once()->with($payload)->andReturn(Mockery::self());
        $this->jws->shouldReceive('sign')->andThrow(new Exception);

        $this->getProvider('secret', 'HS256')->encode($payload);
    }

    /** @test */
    public function it_should_return_the_payload_when_passing_a_valid_token_to_decode()
    {
        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $this->jws->shouldReceive('load')->once()->with('foo.bar.baz', false)->andReturn(Mockery::self());
        $this->jws->shouldReceive('verify')->once()->with('secret', 'HS256')->andReturn(true);
        $this->jws->shouldReceive('getPayload')->andReturn($payload);

        $this->assertSame($payload, $this->getProvider('secret', 'HS256')->decode('foo.bar.baz'));
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\TokenInvalidException
     * @expectedExceptionMessage Token Signature could not be verified.
     */
    public function it_should_throw_a_token_invalid_exception_when_the_token_could_not_be_decoded_due_to_a_bad_signature()
    {
        $this->jws->shouldReceive('load')->once()->with('foo.bar.baz', false)->andReturn(Mockery::self());
        $this->jws->shouldReceive('verify')->once()->with('secret', 'HS256')->andReturn(false);
        $this->jws->shouldReceive('getPayload')->never();

        $this->getProvider('secret', 'HS256')->decode('foo.bar.baz');
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\TokenInvalidException
     * @expectedExceptionMessage Could not decode token:
     */
    public function it_should_throw_a_token_invalid_exception_when_the_token_could_not_be_decoded()
    {
        $this->jws->shouldReceive('load')->once()->with('foo.bar.baz', false)->andThrow(new InvalidArgumentException);
        $this->jws->shouldReceive('verify')->never();
        $this->jws->shouldReceive('getPayload')->never();

        $this->getProvider('secret', 'HS256')->decode('foo.bar.baz');
    }

    /** @test */
    public function it_should_generate_a_token_when_using_an_rsa_algorithm()
    {
        $provider = $this->getProvider(
            'does_not_matter',
            'RS256',
            ['private' => $this->getDummyPrivateKey(), 'public' => $this->getDummyPublicKey()]
        );

        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $this->jws->shouldReceive('setPayload')->once()->with($payload)->andReturn(Mockery::self());
        $this->jws->shouldReceive('sign')->once()->with($this->getDummyPrivateKey(), null)->andReturn(Mockery::self());
        $this->jws->shouldReceive('getTokenString')->once()->andReturn('foo.bar.baz');

        $token = $provider->encode($payload);

        $this->assertSame('foo.bar.baz', $token);
    }

    /** @test */
    public function it_should_generate_a_token_when_using_an_ecdsa_algorithm()
    {
        $provider = $this->getProvider(
            'does_not_matter',
            'ES256',
            ['private' => $this->getDummyPrivateKey(), 'public' => $this->getDummyPublicKey()]
        );

        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $this->jws->shouldReceive('setPayload')->once()->with($payload)->andReturn(Mockery::self());
        $this->jws->shouldReceive('sign')->once()->with($this->getDummyPrivateKey(), null)->andReturn(Mockery::self());
        $this->jws->shouldReceive('getTokenString')->once()->andReturn('foo.bar.baz');

        $token = $provider->encode($payload);

        $this->assertSame('foo.bar.baz', $token);
    }

    /** @test */
    public function it_should_decode_a_token_when_using_an_rsa_algorithm()
    {
        $provider = $this->getProvider(
            'does_not_matter',
            'RS256',
            ['private' => $this->getDummyPrivateKey(), 'public' => $this->getDummyPublicKey()]
        );

        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $this->jws->shouldReceive('setPayload')->once()->with($payload)->andReturn(Mockery::self());
        $this->jws->shouldReceive('sign')->once()->with($this->getDummyPrivateKey(), null)->andReturn(Mockery::self());
        $this->jws->shouldReceive('getTokenString')->once()->andReturn('foo.bar.baz');

        $token = $provider->encode($payload);

        $this->assertSame('foo.bar.baz', $token);
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\JWTException
     * @expectedExceptionMessage The given algorithm could not be found
     */
    public function it_should_throw_a_exception_when_the_algorithm_passed_is_invalid()
    {
        $this->jws->shouldReceive('load')->once()->with('foo.bar.baz', false)->andReturn(Mockery::self());
        $this->jws->shouldReceive('verify')->with('secret', 'AlgorithmWrong')->andReturn(true);

        $this->getProvider('secret', 'AlgorithmWrong')->decode('foo.bar.baz');
    }

    /**
     * @test
     */
    public function it_should_return_the_public_key()
    {
        $provider = $this->getProvider(
            'does_not_matter',
            'RS256',
            $keys = ['private' => $this->getDummyPrivateKey(), 'public' => $this->getDummyPublicKey()]
        );

        $this->assertSame($keys['public'], $provider->getPublicKey());
    }

    /**
     * @test
     */
    public function it_should_return_the_keys()
    {
        $provider = $this->getProvider(
            'does_not_matter',
            'RS256',
            $keys = ['private' => $this->getDummyPrivateKey(), 'public' => $this->getDummyPublicKey()]
        );

        $this->assertSame($keys, $provider->getKeys());
    }

    public function getProvider($secret, $algo, array $keys = [])
    {
        return new Namshi($this->jws, $secret, $algo, $keys);
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
