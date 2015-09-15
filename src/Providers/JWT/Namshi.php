<?php

/*
 * This file is part of jwt-auth
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Providers\JWT;

use Exception;
use Namshi\JOSE\JWS;
use Tymon\JWTAuth\Contracts\Providers\JWT;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class Namshi extends Provider implements JWT
{
    /**
     * @var \Namshi\JOSE\JWS
     */
    protected $jws;

    /**
     * @param string  $secret
     * @param string  $algo
     * @param null    $driver
     */
    public function __construct($secret, $algo, $cert, $driver = null)
    {
        parent::__construct($secret, $algo, $cert);

        $this->jws = $driver ?: new JWS(['typ' => 'JWT', 'alg' => $algo]);
    }

    /**
     * Create a JSON Web Token
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     *
     * @return string
     */
    public function encode(array $payload)
    {
        try {
            $this->jws->setPayload($payload)->sign($this->secret);

            return $this->jws->getTokenString();
        } catch (Exception $e) {
            throw new JWTException('Could not create token: ' . $e->getMessage());
        }
    }

    /**
     * Decode a JSON Web Token
     *
     * @param  string  $token
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     *
     * @return array
     */
    public function decode($token)
    {
        try {
            // let's never allow unsecure tokens
            $jws = $this->jws->load($token, false);
        } catch (Exception $e) {
            throw new TokenInvalidException('Could not decode token: ' . $e->getMessage());
        }

        if (in_array($this->algo, ['RS256']) && $this->cert !== null) {
            $key = $this->cert;
        } else {
            $key = $this->secret;
        }

        if (! $jws->verify($key, $this->algo)) {
            throw new TokenInvalidException('Token Signature could not be verified.');
        }

        return $jws->getPayload();
    }
}
