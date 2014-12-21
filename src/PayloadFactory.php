<?php

namespace Tymon\JWTAuth;

use Illuminate\Http\Request;
use Tymon\JWTAuth\Claims\Factory;
use Tymon\JWTAuth\Payload;

class PayloadFactory
{
    /**
     * @var \Tymon\JWTAuth\Claims\Factory
     */
    protected $claimFactory;

    /**
     * @var \Illuminate\Http\Request
     */
    protected $request;

    /**
     * @var int
     */
    protected $ttl = 60;

    /**
     * @var array
     */
    protected $defaultClaims = ['iss', 'iat', 'exp', 'nbf', 'jti'];

    /**
     * @var array
     */
    protected $claims = [];

    /**
     * @param \Tymon\JWTAuth\Claims\Factory  $claimFactory
     * @param \Illuminate\Http\Request  $request
     */
    public function __construct(Factory $claimFactory, Request $request)
    {
        $this->claimFactory = $claimFactory;
        $this->request = $request;
    }

    /**
     * Create the Payload instance
     *
     * @return \Tymon\JWTAuth\Payload
     */
    public function make(array $customClaims = [])
    {
        $claims = $this->buildClaims($customClaims)->resolveClaims();

        return new Payload($claims);
    }

    /**
     * Add an array of claims to the Payload
     *
     * @param array $claims
     */
    public function addClaims(array $claims)
    {
        foreach ($claims as $name => $value) {
            $this->addClaim($name, $value);
        }

        return $this;
    }

    /**
     * Add a claim to the Payload
     *
     * @param string  $name
     * @param mixed   $value
     */
    public function addClaim($name, $value)
    {
        $this->claims[$name] = $value;

        return $this;
    }

    /**
     * Build the default claims
     *
     * @return \Tymon\JWTAuth\PayloadFactory
     */
    protected function buildClaims(array $customClaims)
    {
        // add the custom claims first
        foreach (array_diff($customClaims, $this->defaultClaims) as $name => $value) {
            $this->addClaim($name, $value);
        }

        foreach ($this->defaultClaims as $claim) {
            if (! array_key_exists($claim, $customClaims)) {
                $this->addClaim($claim, $this->$claim());
            }
        }

        return $this;
    }

    /**
     * Build out the Claim DTO's
     *
     * @return array
     */
    public function resolveClaims()
    {
        $resolved = [];
        foreach ($this->claims as $name => $value) {
            $resolved[] = $this->claimFactory->get($name, $value);
        }

        return $resolved;
    }

    /**
     * Set a unique id (jti) for the token
     *
     * @return string
     */
    protected function jti()
    {
        return md5('jti.'. array_get($this->claims, 'sub', '') . '.' . array_get($this->claims, 'iat', ''));
    }

    /**
     * Set the Issuer (iss) claim
     *
     * @return string
     */
    public function iss()
    {
        return $this->request->url();
    }

    /**
     * Set the Issued At (iat) claim
     *
     * @return int
     */
    public function iat()
    {
        return time();
    }

    /**
     * Set the Expiration (exp) claim
     *
     * @return int
     */
    public function exp()
    {
        return time() + ($this->ttl * 60);
    }

    /**
     * Set the Not Before (nbf) claim
     *
     * @return int
     */
    public function nbf()
    {
        return time();
    }

    /**
     * Set the token ttl (in minutes)
     *
     * @param int
     */
    public function setTTL($ttl)
    {
        $this->ttl = $ttl;

        return $this;
    }

    /**
     * Magically add a claim
     *
     * @param  string  $method
     * @param  array   $parameters
     * @return PayloadFactory
     * @throws \BadMethodCallException
     */
    public function __call($method, $parameters)
    {
        $this->addClaim($method, $parameters[0]);

        return $this;
    }
}
