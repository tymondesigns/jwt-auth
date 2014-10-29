<?php

namespace Tymon\JWTAuth\JWT;

use Illuminate\Http\Request;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Payload;
use Tymon\JWTAuth\Token;

abstract class JWT
{
    /**
     * @var string
     */
    protected $secret;

    /**
     * @var \Illuminate\Http\Request
     */
    protected $request;

    /**
     * @var Token
     */
    protected $token;

    /**
     * @var Payload
     */
    protected $payload;

    /**
     * @var int
     */
    protected $ttl = 120;

    /**
     * @var string
     */
    protected $algo = 'HS256';

    /**
     * @param $secret
     * @param \Illuminate\Http\Request  $request
     */
    public function __construct($secret, Request $request)
    {
        $this->secret = $secret;
        $this->request = $request;
    }

    /**
     * Build the payload for the token
     *
     * @param  mixed  $subject
     * @param  array  $customClaims
     * @return array
     */
    protected function buildPayload($subject, array $customClaims = [])
    {
        $payload = array_merge($customClaims, [
            'iss' => $this->request->url(),
            'sub' => $subject,
            'iat' => time(),
            'exp' => time() + ($this->ttl * 60)
        ]);

        return $this->createPayload($payload)->get();
    }

    /**
     * Create a new Token value object
     *
     * @param  string  $token
     * @return \Tymon\JWTAuth\Token
     */
    protected function createToken($token)
    {
        $this->token = new Token($token);

        return $this->token;
    }

    /**
     * Create a new Payload value object
     *
     * @param  array  $payload
     * @return \Tymon\JWTAuth\Payload
     */
    protected function createPayload($payload)
    {
        $this->payload = new Payload($payload);

        return $this->payload;
    }

    /**
     * Helper method to return the subject claim
     *
     * @param  string  $token
     * @return mixed
     */
    public function getSubject($token = false)
    {
        if (! $token) {

            if (! $this->payload) {
                throw new JWTException('A token is required');
            }

            return $this->payload->get('sub');
        }

        return $this->decode($token)->get('sub');
    }

    /**
     * Get the JWT Payload
     *
     * @return \Tymon\JWTAuth\Payload
     */
    public function getPayload()
    {
        return $this->payload;
    }

    /**
     * Get the JWT
     *
     * @return \Tymon\JWTAuth\Token
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     * Set the ttl of the token
     *
     * @param int  $ttl  in minutes
     */
    public function setTTL($ttl)
    {
        $this->ttl = $ttl;

        return $this;
    }

    /**
     * Set the algorithm of the token
     *
     * @param string  $algo
     */
    public function setAlgo($algo)
    {
        $this->algo = $algo;

        return $this;
    }
}
