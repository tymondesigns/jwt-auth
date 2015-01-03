<?php

namespace Tymon\JWTAuth;

use Carbon\Carbon;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Claims\Factory;

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
     * @var boolean
     */
    protected $refreshFlow = false;

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
     * @param  array  $customClaims
     * @return \Tymon\JWTAuth\Payload
     */
    public function make(array $customClaims = [])
    {
        $claims = $this->buildClaims($customClaims)->resolveClaims();

        return new Payload($claims, $this->refreshFlow);
    }

    /**
     * Add an array of claims to the Payload
     *
     * @param  array  $claims
     * @return $this
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
     * @param  string  $name
     * @param  mixed   $value
     * @return $this
     */
    public function addClaim($name, $value)
    {
        $this->claims[$name] = $value;

        return $this;
    }

    /**
     * Build the default claims
     *
     * @param  array  $customClaims
     * @return $this
     */
    protected function buildClaims(array $customClaims)
    {
        // add any custom claims first
        $this->addClaims(array_diff($customClaims, $this->defaultClaims));

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
        return Carbon::now()->format('U');
    }

    /**
     * Set the Expiration (exp) claim
     *
     * @return int
     */
    public function exp()
    {
        return Carbon::now()->addMinutes($this->ttl)->format('U');
    }

    /**
     * Set the Not Before (nbf) claim
     *
     * @return int
     */
    public function nbf()
    {
        return Carbon::now()->format('U');
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
     * Set the token ttl (in minutes)
     *
     * @param  int  $ttl
     * @return $this
     */
    public function setTTL($ttl)
    {
        $this->ttl = $ttl;

        return $this;
    }

    /**
     * Get the token ttl
     *
     * @return int
     */
    public function getTTL()
    {
        return $this->ttl;
    }

    /**
     * Set the refresh flow
     *
     * @param boolean $refreshFlow
     * @return $this
     */
    public function setRefreshFlow($refreshFlow = true)
    {
        $this->refreshFlow = $refreshFlow;

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
