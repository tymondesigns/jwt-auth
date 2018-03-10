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
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Keychain;
use Illuminate\Support\Collection;
use Tymon\JWTAuth\Contracts\Providers\JWT;
use Tymon\JWTAuth\Exceptions\JWTException;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RS256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as RS384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as RS512;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HS256;
use Lcobucci\JWT\Signer\Hmac\Sha384 as HS384;
use Lcobucci\JWT\Signer\Hmac\Sha512 as HS512;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as ES256;
use Lcobucci\JWT\Signer\Ecdsa\Sha384 as ES384;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as ES512;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class Lcobucci extends Provider implements JWT
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
        'HS256' => HS256::class,
        'HS384' => HS384::class,
        'HS512' => HS512::class,
        'RS256' => RS256::class,
        'RS384' => RS384::class,
        'RS512' => RS512::class,
        'ES256' => ES256::class,
        'ES384' => ES384::class,
        'ES512' => ES512::class,
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
            throw new TokenInvalidException('Could not decode token: '.$e->getMessage(), $e->getCode(), $e);
        }

        if (! $jwt->verify($this->signer, $this->getVerificationKey())) {
            throw new TokenInvalidException('Token Signature could not be verified.');
        }

        return Collection::make($jwt->getClaims())->map(function ($claim) {
            return is_object($claim) ? $claim->getValue() : $claim;
        })->toArray();
    }

    /**
     * Get the signer instance.
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     *
     * @return \Lcobucci\JWT\Signer
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

        return $reflect->isSubclassOf(Rsa::class) || $reflect->isSubclassOf(Ecdsa::class);
    }

    /**
     * {@inheritdoc}
     */
    protected function getSigningKey()
    {
        return $this->isAsymmetric()
            ? (new Keychain())->getPrivateKey($this->getPrivateKey(), $this->getPassphrase())
            : $this->getSecret();
    }

    /**
     * {@inheritdoc}
     */
    protected function getVerificationKey()
    {
        return $this->isAsymmetric()
            ? (new Keychain())->getPublicKey($this->getPublicKey())
            : $this->getSecret();
    }
}
