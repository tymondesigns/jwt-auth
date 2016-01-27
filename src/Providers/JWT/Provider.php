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

abstract class Provider
{
    /**
     * @var string
     */
    protected $secret;

    /**
     * @var string
     */
    protected $algo;

    /**
     * @param string  $secret
     * @param string  $algo
     */
    public function __construct($secret, $algo)
    {
        $this->secret = $secret;
        $this->algo = $algo;
    }

    /**
     * Set the algorithm used to sign the token
     *
     * @param  string  $algo
     *
     * @return $this
     */
    public function setAlgo($algo)
    {
        $this->algo = $algo;

        return $this;
    }

    /**
     * Get the algorithm used to sign the token
     *
     * @return string
     */
    public function getAlgo()
    {
        return $this->algo;
    }
}
