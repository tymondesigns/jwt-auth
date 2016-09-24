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

use Tymon\JWTAuth\Contracts\Providers\JWT;

class Spomky extends Provider implements JWT
{
    /**
     * @param  string  $secret
     * @param  string  $algo
     * @param  array  $keys
     * @param  string|null  $driver
     *
     * @return void
     */
    public function __construct($secret, $algo, array $keys = [], $driver = null)
    {
        parent::__construct($secret, $keys, $algo);
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
        //
    }

    /**
     * Decode a JSON Web Token.
     *
     * @param  string  $token
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     *
     * @return array
     */
    public function decode($token)
    {
        //
    }
}
