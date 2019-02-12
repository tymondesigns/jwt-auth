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
use ReflectionClass;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Builder;
use Illuminate\Support\Collection;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class Lcobucci extends Provider
{
    /**
     * The Builder instance.
     *
     * @var \Lcobucci\JWT\Builder
     */
    protected $builder;

    /**
     * The Parser instance.
     *
     * @var \Lcobucci\JWT\Parser
     */
    protected $parser;

    /**
     * The Signer instance.
     *
     * @var \Lcobucci\JWT\Signer
     */
    protected $signer;

    /**
     * Constructor.
     */
    public function __construct(
        Builder $builder,
        Parser $parser,
        string $secret,
        string $algo,
        array $keys
    ) {
        parent::__construct($secret, $algo, $keys);

        $this->builder = $builder;
        $this->parser = $parser;
        $this->signer = $this->getSigner();
    }

    /**
     * Signers that this provider supports.
     *
     * @var array
     */
    protected $signers = [
        'HS256' => Signer\Hmac\Sha256::class,
        'HS384' => Signer\Hmac\Sha384::class,
        'HS512' => Signer\Hmac\Sha512::class,
        'RS256' => Signer\Rsa\Sha256::class,
        'RS384' => Signer\Rsa\Sha384::class,
        'RS512' => Signer\Rsa\Sha512::class,
        'ES256' => Signer\Ecdsa\Sha256::class,
        'ES384' => Signer\Ecdsa\Sha384::class,
        'ES512' => Signer\Ecdsa\Sha512::class,
    ];

    /**
     * Create a JSON Web Token.
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function encode(array $payload): string
    {
        // Remove the signature on the builder instance first.
        $this->builder->unsign();

        try {
            foreach ($payload as $key => $value) {
                $this->builder->set($key, $value);
            }
            $this->builder->sign($this->signer, $this->getSigningKey());
        } catch (Exception $e) {
            throw new JWTException('Could not create token: '.$e->getMessage(), $e->getCode(), $e);
        }

        return (string) $this->builder->getToken();
    }

    /**
     * Decode a JSON Web Token.
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function decode(string $token): array
    {
        try {
            $jwt = $this->parser->parse($token);
        } catch (Exception $e) {
            throw new TokenInvalidException(
                'Could not decode token: '.$e->getMessage(),
                $e->getCode(),
                $e
            );
        }

        if (! $jwt->verify($this->signer, $this->getVerificationKey())) {
            throw new TokenInvalidException('Token Signature could not be verified.');
        }

        return Collection::make($jwt->getClaims())
            ->map(function ($claim) {
                return is_object($claim) ? $claim->getValue() : $claim;
            })
            ->toArray();
    }

    /**
     * Get the Signer instance.
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    protected function getSigner(): Signer
    {
        if (! array_key_exists($this->algo, $this->signers)) {
            throw new JWTException('The given algorithm could not be found');
        }

        return new $this->signers[$this->algo];
    }

    /**
     * {@inheritdoc}
     */
    protected function isAsymmetric(): bool
    {
        $reflect = new ReflectionClass($this->signer);

        return $reflect->isSubclassOf(Signer\Rsa::class)
            || $reflect->isSubclassOf(Signer\Ecdsa::class);
    }

    /**
     * {@inheritdoc}
     */
    protected function getSigningKey()
    {
        return $this->isAsymmetric()
            ? (new Signer\Keychain())->getPrivateKey($this->getPrivateKey(), $this->getPassphrase())
            : $this->getSecret();
    }

    /**
     * {@inheritdoc}
     */
    protected function getVerificationKey()
    {
        return $this->isAsymmetric()
            ? (new Signer\Keychain())->getPublicKey($this->getPublicKey())
            : $this->getSecret();
    }
}
