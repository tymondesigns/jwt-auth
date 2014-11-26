<?php

namespace Tymon\JWTAuth\Providers\JWT;

use Illuminate\Http\Request;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Payload;
use Tymon\JWTAuth\Token;

abstract class AbstractJWT
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

        $payload['jti'] = $this->createJti($payload);

        return $this->createPayload($payload)->get();
    }

    /**
     * Create a unique id for the token
     *
     * @param  array  $payload
     * @return string
     */
    protected function createJti(array $payload)
    {
        return md5('jti.'. $payload['sub'] . $payload['iat']);
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
    protected function createPayload($payload, $refresh = false)
    {
        $this->payload = new Payload($payload, $refresh);

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
     * Refresh an expired token
     *
     * @param  string  $token
     * @return \Tymon\JWTAuth\Token
     */
    public function refresh($token)
    {
        $subject = $this->decode($this->token, true)->get('sub');

        return $this->encode($subject);
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
