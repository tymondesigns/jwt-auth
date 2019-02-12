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

use Tymon\JWTAuth\Token;
use Tymon\JWTAuth\Factory;
use Tymon\JWTAuth\Options;
use Tymon\JWTAuth\Payload;
use Illuminate\Support\Arr;
use Tymon\JWTAuth\Contracts\Providers\JWT;

abstract class Provider implements JWT
{
    /**
     * The secret.
     *
     * @var string
     */
    protected $secret;

    /**
     * The array of keys.
     *
     * @var array
     */
    protected $keys;

    /**
     * The used algorithm.
     *
     * @var string
     */
    protected $algo;

    /**
     * Constructor.
     */
    public function __construct(string $secret, string $algo, array $keys)
    {
        $this->secret = $secret;
        $this->algo = $algo;
        $this->keys = $keys;
    }

    /**
     * Get the decoded token as a Payload instance.
     */
    public function payload(Token $token, ?Options $options = null): Payload
    {
        return Factory::make($this->decode($token->get()), $options);
    }

    /**
     * Get an encoded Token instance.
     */
    public function token(Payload $payload): Token
    {
        return new Token($this->encode($payload->get()));
    }

    /**
     * Set the algorithm used to sign the token.
     */
    public function setAlgo(string $algo): self
    {
        $this->algo = $algo;

        return $this;
    }

    /**
     * Get the algorithm used to sign the token.
     */
    public function getAlgo(): string
    {
        return $this->algo;
    }

    /**
     * Set the secret used to sign the token.
     */
    public function setSecret(string $secret): self
    {
        $this->secret = $secret;

        return $this;
    }

    /**
     * Get the secret used to sign the token.
     */
    public function getSecret(): string
    {
        return $this->secret;
    }

    /**
     * Set the keys used to sign the token.
     */
    public function setKeys(array $keys): self
    {
        $this->keys = $keys;

        return $this;
    }

    /**
     * Get the array of keys used to sign tokens
     * with an asymmetric algorithm.
     */
    public function getKeys(): array
    {
        return $this->keys;
    }

    /**
     * Get the public key used to sign tokens
     * with an asymmetric algorithm.
     *
     * @return resource|string
     */
    public function getPublicKey()
    {
        return Arr::get($this->keys, 'public');
    }

    /**
     * Get the private key used to sign tokens
     * with an asymmetric algorithm.
     *
     * @return resource|string
     */
    public function getPrivateKey()
    {
        return Arr::get($this->keys, 'private');
    }

    /**
     * Get the passphrase used to sign tokens
     * with an asymmetric algorithm.
     */
    public function getPassphrase(): ?string
    {
        return Arr::get($this->keys, 'passphrase');
    }

    /**
     * Get the key used to sign the tokens.
     *
     * @return resource|string
     */
    protected function getSigningKey()
    {
        return $this->isAsymmetric()
            ? $this->getPrivateKey()
            : $this->getSecret();
    }

    /**
     * Get the key used to verify the tokens.
     *
     * @return resource|string
     */
    protected function getVerificationKey()
    {
        return $this->isAsymmetric()
            ? $this->getPublicKey()
            : $this->getSecret();
    }

    /**
     * Determine if the algorithm is asymmetric, and thus
     * requires a public/private key combo.
     */
    abstract protected function isAsymmetric(): bool;
}
