<?php

namespace Tymon\JWTAuth\Providers\JWT;

use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenBlacklistedException;
use Tymon\JWTAuth\Payload;
use Tymon\JWTAuth\Token;
use Tymon\JWTAuth\Blacklist;

abstract class AbstractJWT
{
    /**
     * @var string
     */
    protected $secret;

    /**
     * @var int
     */
    protected $ttl = 60;

    /**
     * @var string
     */
    protected $algo = 'HS256';

    /**
     * @param $secret
     * @param \Tymon\JWTAuth\Blacklist  $blacklist
     * @param \Illuminate\Http\Request  $request
     */
    public function __construct($secret)
    {
        $this->secret = $secret;
    }

    /**
     * Create a unique id for the token
     *
     * @param  array  $payload
     * @return string
     */
    protected function createJti(array $payload)
    {
        return md5('jti.'. $payload['sub'] . '.' . $payload['iat']);
    }

    /**
     * Set the ttl of the token
     *
     * @param  int  $ttl  in minutes
     * @return self
     */
    public function setTTL($ttl)
    {
        $this->ttl = $ttl;

        return $this;
    }

    /**
     * Set the algorithm used to sign the token
     *
     * @param  string  $algo
     * @return self
     */
    public function setAlgo($algo)
    {
        $this->algo = $algo;

        return $this;
    }

    /**
     * Get the ttl of the token
     *
     * @return int
     */
    public function getTTL()
    {
        return $this->ttl;
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
