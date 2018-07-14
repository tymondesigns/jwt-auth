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
use InvalidArgumentException;
use Ahc\Jwt\JWT;
use Ahc\Jwt\JWTException as ProviderException;
use Tymon\JWTAuth\Providers\JWT\Adhocore;
use Tymon\JWTAuth\Test\AbstractTestCase;

class AdhocoreTest extends AbstractTestCase
{
    /**
     * @var \Mockery\MockInterface
     */
    protected $handler;

    public function setUp()
    {
        $this->handler = Mockery::mock(JWT::class);
    }

    /**
     * @test
     */
    public function it_uses_default_handler_when_not_preset()
    {
        $this->handler = null;

        $this->assertInstanceOf(JWT::class, $this->getProvider('secret', 'HS256')->getHandler());
    }

    /**
     * @test
     */
    public function it_should_return_the_token_when_passing_a_valid_payload_to_encode()
    {
        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $this->handler->shouldReceive('encode')->once()->with($payload)->andReturn('foo.bar.baz');

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

        $this->handler->shouldReceive('encode')->once()->andThrow(new Exception);

        $this->getProvider('secret', 'HS256')->encode($payload);
    }

    /**
     * @test
     */
    public function it_should_return_the_payload_when_passing_a_valid_token_to_decode()
    {
        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $this->handler
            ->shouldReceive('encode')->once()->with($payload)->andReturn('foo.bar.baz')
            ->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($payload)
        ;

        $this->assertSame($payload, $this->getProvider('secret', 'HS256')->decode(
            $this->getProvider('secret', 'HS256')->encode($payload)
        ));
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\TokenInvalidException
     * @expectedExceptionMessage Token Signature could not be verified
     */
    public function it_should_throw_a_token_invalid_exception_when_the_token_could_not_be_decoded_due_to_a_bad_signature()
    {
        $this->handler->shouldReceive('decode')->once()->with('foo.bar.baz')->andThrow(
            new ProviderException('', JWT::ERROR_SIGNATURE_FAILED)
        );

        $this->getProvider('secret', 'HS256')->decode('foo.bar.baz');
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\TokenInvalidException
     * @expectedExceptionMessage Could not decode token:
     */
    public function it_should_throw_a_token_invalid_exception_when_the_token_could_not_be_decoded()
    {
        $this->handler->shouldReceive('decode')->once()->with('foo.bar.baz')->andThrow(new Exception);

        $this->getProvider('secret', 'HS256')->decode('foo.bar.baz');
    }

    /**
     * @test
     */
    public function it_should_generate_a_token_when_using_an_rsa_algorithm()
    {
        $provider = $this->getProvider(
            'does_not_matter',
            'RS256',
            ['private' => $this->getDummyPrivateKey()]
        );

        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $this->handler->shouldReceive('encode')->once()->with($payload)->andReturn('foo.bar.baz');

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
        $this->handler->shouldReceive('decode')->never();

        $this->getProvider('secret', 'NULL')->decode('foo.bar.baz');
    }

    public function getProvider($secret, $algo, array $keys = [])
    {
        return (new Adhocore($secret, $algo, $keys, 1800, 0))->setHandler($this->handler);
    }

    public function getDummyPrivateKey()
    {
        return __DIR__.'/../Keys/id_rsa';
    }
}
