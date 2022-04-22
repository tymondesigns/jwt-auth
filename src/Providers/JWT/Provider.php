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

use Illuminate\Support\Arr;

abstract class Provider
{
    const ALGO_HS256 = 'HS256';
    const ALGO_HS384 = 'HS384';
    const ALGO_HS512 = 'HS512';
    const ALGO_RS256 = 'RS256';
    const ALGO_RS384 = 'RS384';
    const ALGO_RS512 = 'RS512';
    const ALGO_ES256 = 'ES256';
    const ALGO_ES384 = 'ES384';
    const ALGO_ES512 = 'ES512';

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
     *
     * @param  string  $secret
     * @param  string  $algo
     * @param  array  $keys
     * @return void
     */
    public function __construct($secret, $algo, array $keys)
    {
        $this->secret = $secret;
        $this->algo = $algo;
        $this->keys = $keys;
    }

    /**
     * Set the algorithm used to sign the token.
     *
     * @param  string  $algo
     * @return $this
     */
    public function setAlgo($algo)
    {
        $this->algo = $algo;

        return $this;
    }

    /**
     * Get the algorithm used to sign the token.
     *
     * @return string
     */
    public function getAlgo()
    {
        return $this->algo;
    }

    /**
     * Set the secret used to sign the token.
     *
     * @param  string  $secret
     * @return $this
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;

        return $this;
    }

    /**
     * Get the secret used to sign the token.
     *
     * @return string
     */
    public function getSecret()
    {
        return $this->secret;
    }

    /**
     * Set the keys used to sign the token.
     *
     * @param  array  $keys
     * @return $this
     */
    public function setKeys(array $keys)
    {
        $this->keys = $keys;

        return $this;
    }

    /**
     * Get the array of keys used to sign tokens with an asymmetric algorithm.
     *
     * @return array
     */
    public function getKeys()
    {
        return $this->keys;
    }

    /**
     * Get the public key used to sign tokens with an asymmetric algorithm.
     *
     * @return string|null
     */
    public function getPublicKey()
    {
        return Arr::get($this->keys, 'public');
    }

    /**
     * Get the private key used to sign tokens with an asymmetric algorithm.
     *
     * @return string|null
     */
    public function getPrivateKey()
    {
        return Arr::get($this->keys, 'private');
    }

    /**
     * Get the passphrase used to sign tokens
     * with an asymmetric algorithm.
     *
     * @return string|null
     */
    public function getPassphrase()
    {
        return Arr::get($this->keys, 'passphrase');
    }

    /**
     * Get the key used to sign the tokens.
     *
     * @return string|null
     */
    protected function getSigningKey()
    {
        return $this->isAsymmetric() ? $this->getPrivateKey() : $this->getSecret();
    }

    /**
     * Get the key used to verify the tokens.
     *
     * @return string|null
     */
    protected function getVerificationKey()
    {
        return $this->isAsymmetric() ? $this->getPublicKey() : $this->getSecret();
    }

    /**
     * Determine if the algorithm is asymmetric, and thus requires a public/private key combo.
     *
     * @return bool
     */
    abstract protected function isAsymmetric();
}
