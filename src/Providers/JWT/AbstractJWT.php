<?php

namespace Tymon\JWTAuth\Providers\JWT;

use Illuminate\Http\Request;
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
     * @var \Tymon\JWTAuth\Blacklist
     */
    protected $blacklist;

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
     * @var boolean
     */
    protected $refreshFlow = false;

    /**
     * @param $secret
     * @param \Tymon\JWTAuth\Blacklist  $blacklist
     * @param \Illuminate\Http\Request  $request
     */
    public function __construct($secret, Blacklist $blacklist, Request $request)
    {
        $this->secret = $secret;
        $this->blacklist = $blacklist;
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
        return md5('jti.'. $payload['sub'] . '.' . $payload['iat']);
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
        // if config set to check storage
        $this->validateBlacklist($payload);

        $this->payload = new Payload($payload, $this->refreshFlow);

        return $this->payload;
    }

    /**
     * Set the refresh flow flag
     *
     * @param bool  $refreshFlow
     */
    protected function setRefreshFlow($refreshFlow = true)
    {
        $this->refreshFlow = $refreshFlow;

        return $this;
    }

    /**
     * Check whether the token has been blacklisted
     *
     * @param  array  $payload
     * @return bool
     */
    protected function validateBlacklist(array $payload)
    {
        if ($this->blacklist->has($payload['jti'])) {
            throw new TokenBlacklistedException('Token has been blacklisted');
        }

        return true;
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
                throw new JWTException('A token is required', 400);
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
        $subject = $this->setRefreshFlow()->decode($token)->get('sub');

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
     * Get the Blacklist instance
     * 
     * @return \Tymon\JWTAuth\Blacklist
     */
    public function getBlacklist()
    {
        return $this->blacklist;
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
