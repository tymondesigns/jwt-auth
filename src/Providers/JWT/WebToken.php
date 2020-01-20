<?php

declare(strict_types=1);

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Providers\JWT;

use Exception;
use RuntimeException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Algorithm;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWSVerifier;
use Tymon\JWTAuth\Exceptions\JWTException;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Checker\HeaderCheckerManager;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Jose\Component\Signature\Algorithm as Algorithms;
use Jose\Component\Signature\Serializer\JWSSerializer;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;

class WebToken extends Provider
{
    /**
     * Algorithms that this provider supports.
     */
    protected array $algorithms = [
        'HS256' => Algorithms\HS256::class,
        'HS384' => Algorithms\HS384::class,
        'HS512' => Algorithms\HS512::class,
        'RS256' => Algorithms\RS256::class,
        'RS384' => Algorithms\RS384::class,
        'RS512' => Algorithms\RS512::class,
        'ES256' => Algorithms\ES256::class,
        'ES384' => Algorithms\ES384::class,
        'ES512' => Algorithms\ES512::class,
    ];

    /**
     * Create a JSON Web Token.
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function encode(array $payload): string
    {
        try {
            $jws = $this->getJWSBuilder()
                ->create()
                ->withPayload(json_encode($payload))
                ->addSignature($this->getJWK(), ['alg' => $this->getAlgo()])
                ->build();
        } catch (RuntimeException $e) {
            throw new JWTException('Could not create token: '.$e->getMessage(), $e->getCode(), $e);
        }

        return $this->getSerializer()->serialize($jws);
    }

    /**
     * Decode a JSON Web Token.
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function decode(string $token): array
    {
        $signature = 0;

        try {
            $jws = $this->getJWSLoader()->loadAndVerifyWithKey($token, $this->getJWK(), $signature);
        } catch (Exception $e) {
            throw new TokenInvalidException('Token Signature could not be verified.', $e->getCode(), $e);
        }

        return json_decode($jws->getPayload(), true);
    }

    /**
     * Get the Algorithm instance.
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    protected function getAlgorithm(): Algorithm
    {
        if (! array_key_exists($this->algo, $this->algorithms)) {
            throw new JWTException('The given algorithm could not be found');
        }

        return new $this->algorithms[$this->algo];
    }

    /**
     * {@inheritdoc}
     */
    protected function isAsymmetric(): bool
    {
        return ! in_array('oct', $this->getAlgorithm()->allowedKeyTypes());
    }

    /**
     * Get the JWK used to create and verify the token.
     */
    protected function getJWK(): JWK
    {
        if ($this->isAsymmetric()) {
            return JWKFactory::createFromKeyFile($this->getPrivateKey(), $this->getPassphrase(), [
                'use' => 'sig',
            ]);
        }

        return JWKFactory::createFromSecret($this->getSecret(), [
            'alg' => $this->getAlgo(),
            'use' => 'sig'
        ]);
    }

    /**
     * Get the JWS builder.
     */
    protected function getJWSBuilder(): JWSBuilder
    {
        return new JWSBuilder($this->getAlgorithmManager());
    }

    /**
     * Get the JWS loader.
     */
    protected function getJWSLoader(): JWSLoader
    {
        return new JWSLoader(
            $this->getSerializerManager(),
            new JWSVerifier($this->getAlgorithmManager()),
            $this->getHeaderCheckerManager()
        );
    }

    /**
     * Get the JWS serializer.
     */
    protected function getSerializer(): JWSSerializer
    {
        return new CompactSerializer();
    }

    /**
     * Get the algorithm manager.
     */
    protected function getAlgorithmManager(): AlgorithmManager
    {
        return new AlgorithmManager([
            $this->getAlgorithm(),
        ]);
    }

    /**
     * Get the serializer manager.
     */
    protected function getSerializerManager(): JWSSerializerManager
    {
        return new JWSSerializerManager([
            $this->getSerializer(),
        ]);
    }

    /**
     * Get the header checker manager.
     */
    protected function getHeaderCheckerManager(): HeaderCheckerManager
    {
        return new HeaderCheckerManager([
            new AlgorithmChecker([$this->getAlgo()]),
        ], [
            new JWSTokenSupport(),
        ]);
    }
}
