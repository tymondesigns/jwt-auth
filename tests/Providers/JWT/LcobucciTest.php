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

use Exception;
use InvalidArgumentException;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RS256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Validation\Constraint;
use Mockery;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Providers\JWT\Lcobucci;
use Tymon\JWTAuth\Test\AbstractTestCase;

class LcobucciTest extends AbstractTestCase
{
    /**
     * Mocks {@see Configuration}.
     *
     * @var \Mockery\MockInterface
     */
    protected $config;

    /**
     * @var \Mockery\MockInterface
     */
    protected $parser;

    /**
     * @var \Mockery\MockInterface
     */
    protected $builder;

    /**
     * @var \Mockery\MockInterface
     */
    protected $validator;

    public function setUp(): void
    {
        parent::setUp();

        $this->builder = Mockery::mock(Builder::class);
        $this->parser = Mockery::mock(Parser::class);
    }

    /** @test */
    public function it_should_return_the_token_when_passing_a_valid_payload_to_encode()
    {
        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $dataSet = new DataSet($payload, 'payload');

        $this->builder->shouldReceive('relatedTo')->once()->andReturnSelf(); // sub
        $this->builder->shouldReceive('expiresAt')->once()->andReturnSelf(); // exp
        $this->builder->shouldReceive('issuedAt')->once()->andReturnSelf();  // iat
        $this->builder->shouldReceive('issuedBy')->once()->andReturnSelf();  // iss
        $this->builder
            ->shouldReceive('getToken')
            ->once()
            ->with(\Mockery::type(Signer::class), \Mockery::type(Key::class))
            ->andReturn(new Token\Plain(new DataSet([], 'header'), $dataSet, (new Token\Signature('', 'signature'))));

        /** @var Token $token */
        $token = $this->getProvider('secret', 'HS256')->encode($payload);

        $this->assertSame('header.payload.signature', $token);
    }

    /** @test */
    public function it_should_throw_an_invalid_exception_when_the_payload_could_not_be_encoded()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('Could not create token:');

        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $this->builder->shouldReceive('relatedTo')->once()->andReturnSelf(); // sub
        $this->builder->shouldReceive('expiresAt')->once()->andReturnSelf(); // exp
        $this->builder->shouldReceive('issuedAt')->once()->andReturnSelf();  // iat
        $this->builder->shouldReceive('issuedBy')->once()->andReturnSelf();  // iss
        $this->builder
            ->shouldReceive('getToken')
            ->once()
            ->with(\Mockery::type(Signer::class), \Mockery::type(Key::class))
            ->andThrow(new Exception);

        $this->getProvider('secret', 'HS256')->encode($payload);
    }

    /** @test */
    public function it_should_return_the_payload_when_passing_a_valid_token_to_decode()
    {
        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $token = Mockery::mock(Token::class);
        $dataSet = Mockery::mock(new DataSet($payload, 'payload'));

        $provider = $this->getProvider('secret', 'HS256');

        $this->parser->shouldReceive('parse')->once()->with('foo.bar.baz')->andReturn($token);
        $this->validator->shouldReceive('validate')->once()->with($token, Mockery::any())->andReturnTrue();
        $token->shouldReceive('claims')->once()->andReturn($dataSet);
        $dataSet->shouldReceive('all')->once()->andReturn($payload);

        $this->assertSame($payload, $provider->decode('foo.bar.baz'));
    }

    /** @test */
    public function it_should_throw_a_token_invalid_exception_when_the_token_could_not_be_decoded_due_to_a_bad_signature()
    {
        $token = Mockery::mock(Token::class);
        $dataSet = Mockery::mock(new DataSet(['pay', 'load'], 'payload'));

        $provider = $this->getProvider('secret', 'HS256');

        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Token Signature could not be verified.');

        $this->parser->shouldReceive('parse')->once()->with('foo.bar.baz')->andReturn($token);
        $this->validator->shouldReceive('validate')->once()->with($token, Mockery::any())->andReturnFalse();
        $token->shouldReceive('claims')->never();
        $dataSet->shouldReceive('all')->never();

        $provider->decode('foo.bar.baz');
    }

    /** @test */
    public function it_should_throw_a_token_invalid_exception_when_the_token_could_not_be_decoded()
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Could not decode token:');

        $this->parser->shouldReceive('parse')->once()->with('foo.bar.baz')->andThrow(new InvalidArgumentException);
        $this->parser->shouldReceive('verify')->never();
        $this->parser->shouldReceive('getClaims')->never();

        $this->getProvider('secret', 'HS256')->decode('foo.bar.baz');
    }

    /** @test */
    public function it_should_generate_a_token_when_using_an_rsa_algorithm()
    {
        $dummyPrivateKey = $this->getDummyPrivateKey();
        $dummyPublicKey = $this->getDummyPublicKey();

        $provider = $this->getProvider(
            'does_not_matter',
            'RS256',
            ['private' => $dummyPrivateKey, 'public' => $dummyPublicKey]
        );

        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $dataSet = new DataSet($payload, 'payload');

        $this->builder->shouldReceive('relatedTo')->once()->andReturnSelf(); // sub
        $this->builder->shouldReceive('expiresAt')->once()->andReturnSelf(); // exp
        $this->builder->shouldReceive('issuedAt')->once()->andReturnSelf();  // iat
        $this->builder->shouldReceive('issuedBy')->once()->andReturnSelf();  // iss
        $this->builder
            ->shouldReceive('getToken')
            ->once()
            ->with(Mockery::type(RS256::class), Mockery::type(Key::class))
            ->andReturn(new Token\Plain(new DataSet([], 'header'), $dataSet, (new Token\Signature('', 'signature'))));

        $token = $provider->encode($payload);

        $this->assertSame('header.payload.signature', $token);
    }

    /** @test */
    public function it_should_throw_a_exception_when_the_algorithm_passed_is_invalid()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('The given algorithm could not be found');

        $this->parser->shouldReceive('parse')->never();
        $this->parser->shouldReceive('verify')->never();

        $this->getProvider('secret', 'AlgorithmWrong')->decode('foo.bar.baz');
    }

    /** @test */
    public function it_should_return_the_public_key()
    {
        $provider = $this->getProvider(
            'does_not_matter',
            'RS256',
            $keys = ['private' => $this->getDummyPrivateKey(), 'public' => $this->getDummyPublicKey()]
        );

        $this->assertSame($keys['public'], $provider->getPublicKey());
    }

    /** @test */
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
        $provider = new Lcobucci($secret, $algo, $keys);

        $this->validator = Mockery::mock(\Lcobucci\JWT\Validator::class);
        $this->config = Mockery::mock($provider->getConfig());

        $provider = new Lcobucci($secret, $algo, $keys, $this->config);

        $this->config->shouldReceive('builder')->andReturn($this->builder);
        $this->config->shouldReceive('parser')->andReturn($this->parser);
        $this->config->shouldReceive('validator')->andReturn($this->validator);

        $constraint = Mockery::mock(Constraint::class);
        $constraint->shouldReceive('assert')->andReturn();
        $this->config->shouldReceive('validationConstraints')->andReturn([$constraint]);

        return $provider;
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
