<?php

namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Providers\JWT\JWTInterface;
use Tymon\JWTAuth\Exceptions\TokenBlacklistedException;

class JWTManager
{

    /**
     * @var \Tymon\JWTAuth\Providers\JWT\JWTInterface
     */
    protected $jwt;

    /**
     * @var \Tymon\JWTAuth\Blacklist
     */
    protected $blacklist;

    /**
     * @var \Tymon\JWTAuth\PayloadFactory
     */
    protected $payloadFactory;

    /**
     *  @param \Tymon\JWTAuth\Providers\JWT\JWTInterface  $jwt
     *  @param \Tymon\JWTAuth\Blacklist  $blacklist
     *  @param \Tymon\JWTAuth\PayloadFactory  $payloadFactory
     */
    public function __construct(JWTInterface $jwt, Blacklist $blacklist, PayloadFactory $payloadFactory)
    {
        $this->jwt = $jwt;
        $this->blacklist = $blacklist;
        $this->payloadFactory = $payloadFactory;
    }

    /**
     * Encode a Payload and return the Token
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     * @return \Tymon\JWTAuth\Token
     */
    public function encode(Payload $payload)
    {
        $token = $this->jwt->encode($payload->get());

        return new Token($token);
    }

    /**
     * Decode a Token and return the Payload
     *
     * @param  \Tymon\JWTAuth\Token $token
     * @throws Exceptions\TokenBlacklistedException
     * @return \Tymon\JWTAuth\Payload
     */
    public function decode(Token $token)
    {
        $payloadArray = $this->jwt->decode($token->get());

        $payload = $this->payloadFactory->make($payloadArray);

        if ($this->blacklist->has($payload)) {
            throw new TokenBlacklistedException('The token has been blacklisted');
        }

        return $payload;
    }

    /**
     * Refresh a Token and return a new Token
     *
     * @param  \Tymon\JWTAuth\Token  $token
     * @return \Tymon\JWTAuth\Token
     */
    public function refresh(Token $token)
    {
        $payload = $this->decode($token);

        // invalidate old token
        $this->blacklist->add($payload);

        // return the new token
        return $this->encode($this->payloadFactory->setRefreshFlow()->make(['sub' => $payload['sub']]));
    }

    /**
     * Invalidate a Token by adding it to the blacklist
     *
     * @param  Token  $token
     * @return boolean
     */
    public function invalidate(Token $token)
    {
        return $this->blacklist->add($this->decode($token));
    }

    /**
     * Get the PayloadFactory instance
     *
     * @return \Tymon\JWTAuth\PayloadFactory
     */
    public function getPayloadFactory()
    {
        return $this->payloadFactory;
    }

    /**
     * Get the JWTProvider instance
     *
     * @return \Tymon\JWTAuth\Providers\JWT\JWTInterface
     */
    public function getJWTProvider()
    {
        return $this->jwt;
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
}
