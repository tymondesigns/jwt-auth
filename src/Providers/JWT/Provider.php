<?php declare(strict_types=1);

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
    public function __construct(string $secret, array $keys, string $algo)
    {
        $this->secret = $secret;
        $this->keys = $keys;
        $this->algo = $algo;
    }

    /**
     * Set the algorithm used to sign the token.
     *
     *
     * @return $this
     */
    public function setAlgo(string $algo)
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
     *
     *
     * @return $this
     */
    public function setSecret(string $secret)
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
    public function getPassphrase(): string
    {
        return Arr::get($this->keys, 'passphrase');
    }
}
