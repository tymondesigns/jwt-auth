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

use Exception;
use Ahc\Jwt\JWT;
use Tymon\JWTAuth\Exceptions\JWTException;
use Ahc\Jwt\JWTException as ProviderException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Contracts\Providers\JWT as Contract;

class Adhocore extends Provider implements Contract
{
    /**
     * The token time to live in seconds.
     *
     * @var int
     */
    protected $ttl;

    /**
     * The grace time in seconds to allow for clock skew.
     *
     * @var int
     */
    protected $leeway;

    /**
     * The JWT handler.
     *
     * @var JWT
     */
    protected $handler;

    /**
     * Constructor.
     *
     * @param  string  $secret
     * @param  string  $algo
     * @param  array   $keys
     * @param  int     $ttl
     * @param  int     $leeway
     *
     * @return void
     */
    public function __construct($secret, $algo, array $keys, $ttl, $leeway)
    {
        $this->ttl = $ttl;
        $this->leeway = $leeway;

        parent::__construct($secret, $algo, $keys);
    }

    /**
     * Get the JWT handler.
     *
     * @return JWT
     */
    public function getHandler()
    {
        if (! in_array($this->algo, ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'])) {
            throw new JWTException('The given algorithm could not be found');
        }

        if (! $this->handler) {
            $key = $this->isAsymmetric() ? $this->getPrivateKey() : $this->secret;

            $this->handler = new JWT($key, $this->algo, $this->ttl, $this->leeway, $this->getPassphrase());
        }

        return $this->handler;
    }

    /**
     * Set the JWT handler.
     *
     * @param JWT|null $handler
     *
     * @return $this
     */
    public function setHandler(JWT $handler = null)
    {
        $this->handler = $handler;

        return $this;
    }

    /**
     * Create a JSON Web Token.
     *
     * @param  array  $payload
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     *
     * @return string
     */
    public function encode(array $payload)
    {
        try {
            return $this->getHandler()->encode($payload);
        } catch (Exception $e) {
            throw new JWTException('Could not create token: '.$e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Decode a JSON Web Token.
     *
     * @param  string  $token
     *
     * @throws \Tymon\JWTAuth\Exceptions\TokenInvalidException
     *
     * @return array
     */
    public function decode($token)
    {
        try {
            return $this->getHandler()->decode($token);
        } catch (Exception $e) {
            $message = 'Could not decode token: '.$e->getMessage();
        }

        if ($e instanceof ProviderException && $e->getCode() === JWT::ERROR_SIGNATURE_FAILED) {
            $message = 'Token Signature could not be verified';
        }

        throw new TokenInvalidException($message, $e->getCode(), $e);
    }

    /**
     * {@inheritdoc}
     */
    protected function isAsymmetric()
    {
        return \substr($this->algo, 0, 2) !== 'HS';
    }
}
