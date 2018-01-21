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
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use InvalidArgumentException;
use Tymon\JWTAuth\Test\AbstractTestCase;
use Tymon\JWTAuth\Providers\JWT\Lcobucci;

class LcobucciTest extends AbstractTestCase
{
    /**
     * @var \Mockery\MockInterface
     */
    protected $parser;

    /**
     * @var \Mockery\MockInterface
     */
    protected $builder;

    /**
     * @var \Tymon\JWTAuth\Providers\JWT\Namshi
     */
    protected $provider;

    public function setUp()
    {
        parent::setUp();

        $this->builder = Mockery::mock(Builder::class);
        $this->parser = Mockery::mock(Parser::class);
    }

    /** @test */
    public function it_should_return_the_token_when_passing_a_valid_payload_to_encode()
    {
        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $this->builder->shouldReceive('unsign')->once()->andReturnSelf();
        $this->builder->shouldReceive('set')->times(count($payload));
        $this->builder->shouldReceive('sign')->once()->with(Mockery::any(), 'secret');
        $this->builder->shouldReceive('getToken')->once()->andReturn('foo.bar.baz');

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

        $this->builder->shouldReceive('unsign')->once()->andReturnSelf();
        $this->builder->shouldReceive('set')->times(count($payload));
        $this->builder->shouldReceive('sign')->once()->with(Mockery::any(), 'secret')->andThrow(new Exception);

        $this->getProvider('secret', 'HS256')->encode($payload);
    }

    /** @test */
    public function it_should_return_the_payload_when_passing_a_valid_token_to_decode()
    {
        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $this->parser->shouldReceive('parse')->once()->with('foo.bar.baz')->andReturn(Mockery::self());
        $this->parser->shouldReceive('verify')->once()->with(Mockery::any(), 'secret')->andReturn(true);
        $this->parser->shouldReceive('getClaims')->once()->andReturn($payload);

        $this->assertSame($payload, $this->getProvider('secret', 'HS256')->decode('foo.bar.baz'));
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\TokenInvalidException
     * @expectedExceptionMessage Token Signature could not be verified.
     */
    public function it_should_throw_a_token_invalid_exception_when_the_token_could_not_be_decoded_due_to_a_bad_signature()
    {
        $this->parser->shouldReceive('parse')->once()->with('foo.bar.baz')->andReturn(Mockery::self());
        $this->parser->shouldReceive('verify')->once()->with(Mockery::any(), 'secret')->andReturn(false);
        $this->parser->shouldReceive('getClaims')->never();

        $this->getProvider('secret', 'HS256')->decode('foo.bar.baz');
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\TokenInvalidException
     * @expectedExceptionMessage Could not decode token:
     */
    public function it_should_throw_a_token_invalid_exception_when_the_token_could_not_be_decoded()
    {
        $this->parser->shouldReceive('parse')->once()->with('foo.bar.baz')->andThrow(new InvalidArgumentException);
        $this->parser->shouldReceive('verify')->never();
        $this->parser->shouldReceive('getClaims')->never();

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

        $this->builder->shouldReceive('unsign')->once()->andReturnSelf();
        $this->builder->shouldReceive('set')->times(count($payload));
        $this->builder->shouldReceive('sign')->once()->with(Mockery::any(), Mockery::type(Key::class));
        $this->builder->shouldReceive('getToken')->once()->andReturn('foo.bar.baz');

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
        $this->parser->shouldReceive('parse')->never();
        $this->parser->shouldReceive('verify')->never();

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
        return new Lcobucci($this->builder, $this->parser, $secret, $algo, $keys);
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
