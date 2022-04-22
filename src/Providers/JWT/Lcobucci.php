<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Providers\JWT;

use DateTimeImmutable;
use DateTimeInterface;
use Exception;
use Illuminate\Support\Collection;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Tymon\JWTAuth\Contracts\Providers\JWT;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class Lcobucci extends Provider implements JWT
{
    /**
     * \Lcobucci\JWT\Signer.
     */
    protected $signer;

    /**
     * \Lcobucci\JWT\Configuration.
     */
    protected $config;

    /**
     * Create the Lcobucci provider.
     *
     * @param  string  $secret
     * @param  string  $algo
     * @param  array  $keys
     * @param  \Lcobucci\JWT\Configuration|null  $config
     * @return void
     */
    public function __construct($secret, $algo, array $keys, $config = null)
    {
        parent::__construct($secret, $algo, $keys);

        $this->signer = $this->getSigner();
        $this->config = $config ?: $this->buildConfig();
    }

    /**
     * Signers that this provider supports.
     *
     * @var array
     */
    protected $signers = [
        self::ALGO_HS256 => Signer\Hmac\Sha256::class,
        self::ALGO_HS384 => Signer\Hmac\Sha384::class,
        self::ALGO_HS512 => Signer\Hmac\Sha512::class,
        self::ALGO_RS256 => Signer\Rsa\Sha256::class,
        self::ALGO_RS384 => Signer\Rsa\Sha384::class,
        self::ALGO_RS512 => Signer\Rsa\Sha512::class,
        self::ALGO_ES256 => Signer\Ecdsa\Sha256::class,
        self::ALGO_ES384 => Signer\Ecdsa\Sha384::class,
        self::ALGO_ES512 => Signer\Ecdsa\Sha512::class,
    ];

    /**
     * Create a JSON Web Token.
     *
     * @param  array  $payload
     * @return string
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function encode(array $payload)
    {
        $builder = $this->getBuilderFromClaims($payload);

        try {
            return $builder
                ->getToken($this->config->signer(), $this->config->signingKey())
                ->toString();
        } catch (Exception $e) {
            throw new JWTException('Could not create token: '.$e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Decode a JSON Web Token.
     *
     * @param  string  $token
     * @return array
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function decode($token)
    {
        try {
            /** @var \Lcobucci\JWT\Token\Plain */
            $token = $this->config->parser()->parse($token);
        } catch (Exception $e) {
            throw new TokenInvalidException('Could not decode token: '.$e->getMessage(), $e->getCode(), $e);
        }

        if (! $this->config->validator()->validate($token, ...$this->config->validationConstraints())) {
            throw new TokenInvalidException('Token Signature could not be verified.');
        }

        return Collection::wrap($token->claims()->all())
            ->map(function ($claim) {
                if ($claim instanceof DateTimeInterface) {
                    return $claim->getTimestamp();
                }

                return is_object($claim) && method_exists($claim, 'getValue')
                    ? $claim->getValue()
                    : $claim;
            })
            ->toArray();
    }

    /**
     * Create an instance of the builder with all of the claims applied.
     *
     * @param  array  $payload
     * @return \Lcobucci\JWT\Token\Builder
     */
    protected function getBuilderFromClaims(array $payload): Builder
    {
        $builder = $this->config->builder();

        foreach ($payload as $key => $value) {
            switch ($key) {
                case RegisteredClaims::ID:
                    $builder->identifiedBy($value);
                    break;
                case RegisteredClaims::EXPIRATION_TIME:
                    $builder->expiresAt(DateTimeImmutable::createFromFormat('U', $value));
                    break;
                case RegisteredClaims::NOT_BEFORE:
                    $builder->canOnlyBeUsedAfter(DateTimeImmutable::createFromFormat('U', $value));
                    break;
                case RegisteredClaims::ISSUED_AT:
                    $builder->issuedAt(DateTimeImmutable::createFromFormat('U', $value));
                    break;
                case RegisteredClaims::ISSUER:
                    $builder->issuedBy($value);
                    break;
                case RegisteredClaims::AUDIENCE:
                    $builder->permittedFor($value);
                    break;
                case RegisteredClaims::SUBJECT:
                    $builder->relatedTo($value);
                    break;
                default:
                    $builder->withClaim($key, $value);
            }
        }

        return $builder;
    }

    /**
     * Build the configuration.
     *
     * @return \Lcobucci\JWT\Configuration
     */
    protected function buildConfig(): Configuration
    {
        $config = $this->isAsymmetric()
            ? Configuration::forAsymmetricSigner(
                $this->signer,
                $this->getSigningKey(),
                $this->getVerificationKey()
            )
            : Configuration::forSymmetricSigner($this->signer, $this->getSigningKey());

        $config->setValidationConstraints(
            new SignedWith($this->signer, $this->getVerificationKey())
        );

        return $config;
    }

    /**
     * Get the signer instance.
     *
     * @return \Lcobucci\JWT\Signer
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    protected function getSigner()
    {
        if (! array_key_exists($this->algo, $this->signers)) {
            throw new JWTException('The given algorithm could not be found');
        }

        $signer = $this->signers[$this->algo];

        if (is_subclass_of($signer, Ecdsa::class)) {
            return $signer::create();
        }

        return new $signer();
    }

    /**
     * {@inheritdoc}
     */
    protected function isAsymmetric()
    {
        return is_subclass_of($this->signer, Rsa::class)
            || is_subclass_of($this->signer, Ecdsa::class);
    }

    /**
     * {@inheritdoc}
     *
     * @return \Lcobucci\JWT\Signer\Key
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    protected function getSigningKey()
    {
        if ($this->isAsymmetric()) {
            if (! $privateKey = $this->getPrivateKey()) {
                throw new JWTException('Private key is not set.');
            }

            return $this->getKey($privateKey, $this->getPassphrase() ?? '');
        }

        if (! $secret = $this->getSecret()) {
            throw new JWTException('Secret is not set.');
        }

        return $this->getKey($secret);
    }

    /**
     * {@inheritdoc}
     *
     * @return \Lcobucci\JWT\Signer\Key
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    protected function getVerificationKey()
    {
        if ($this->isAsymmetric()) {
            if (! $public = $this->getPublicKey()) {
                throw new JWTException('Public key is not set.');
            }

            return $this->getKey($public);
        }

        if (! $secret = $this->getSecret()) {
            throw new JWTException('Secret is not set.');
        }

        return $this->getKey($secret);
    }

    /**
     * Get the signing key instance.
     */
    protected function getKey(string $contents, string $passphrase = ''): Key
    {
        return InMemory::plainText($contents, $passphrase);
    }
}
