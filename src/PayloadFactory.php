<?php

namespace Tymon\JWTAuth;

use Illuminate\Http\Request;
use Tymon\JWTAuth\Claims\Factory;
use Illuminate\Support\Collection;
use Tymon\JWTAuth\Validators\PayloadValidator;

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
     * @var \Tymon\JWTAuth\Validators\PayloadValidator
     */
    protected $validator;

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
     * @var \Illuminate\Support\Collection
     */
    protected $claims;

    /**
     * @param \Tymon\JWTAuth\Claims\Factory               $claimFactory
     * @param \Illuminate\Http\Request                    $request
     * @param \Tymon\JWTAuth\Validators\PayloadValidator  $validator
     */
    public function __construct(Factory $claimFactory, Request $request, PayloadValidator $validator)
    {
        $this->claimFactory = $claimFactory;
        $this->request = $request;
        $this->validator = $validator;

        $this->claims = new Collection;
    }

    /**
     * Create the Payload instance
     *
     * @param  array  $customClaims
     *
     * @return \Tymon\JWTAuth\Payload
     */
    public function make(array $customClaims = [])
    {
        $claims = $this->buildClaims($customClaims)
                       ->resolveClaims()
                       ->toArray();

        return new Payload($claims, $this->validator, $this->refreshFlow);
    }

    /**
     * Add an array of claims to the Payload
     *
     * @param  array  $claims
     *
     * @return PayloadFactory
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
     *
     * @return PayloadFactory
     */
    public function addClaim($name, $value)
    {
        $this->claims->put($name, $value);

        return $this;
    }

    /**
     * Build the default claims
     *
     * @param  array  $customClaims
     *
     * @return PayloadFactory
     */
    protected function buildClaims(array $customClaims)
    {
        // add any custom claims first
        $this->addClaims(array_diff_key($customClaims, $this->defaultClaims));

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
     * @return \Illuminate\Support\Collection
     */
    public function resolveClaims()
    {
        return $this->claims->map(function ($value, $name) {
            return $this->claimFactory->get($name, $value);
        });
    }

    /**
     * Get the Issuer (iss) claim
     *
     * @return string
     */
    public function iss()
    {
        return $this->request->url();
    }

    /**
     * Get the Issued At (iat) claim
     *
     * @return int
     */
    public function iat()
    {
        return Utils::now()->format('U');
    }

    /**
     * Get the Expiration (exp) claim
     *
     * @return int
     */
    public function exp()
    {
        return Utils::now()->addMinutes($this->ttl)->format('U');
    }

    /**
     * Get the Not Before (nbf) claim
     *
     * @return int
     */
    public function nbf()
    {
        return Utils::now()->format('U');
    }

    /**
     * Get a unique id (jti) for the token
     *
     * @return string
     */
    protected function jti()
    {
        return md5($this->claims->toJson());
    }

    /**
     * Set the token ttl (in minutes)
     *
     * @param  int  $ttl
     *
     * @return PayloadFactory
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
     *
     * @return PayloadFactory
     */
    public function setRefreshFlow($refreshFlow = true)
    {
        $this->refreshFlow = $refreshFlow;

        return $this;
    }

    /**
     * Set the default claims to be added to the Payload
     *
     * @param array $claims
     *
     * @return PayloadFactory
     */
    public function setDefaultClaims(array $claims)
    {
        $this->defaultClaims = $claims;

        return $this;
    }

    /**
     * Magically add a claim
     *
     * @param  string  $method
     * @param  array   $parameters
     *
     * @throws \BadMethodCallException
     *
     * @return PayloadFactory
     */
    public function __call($method, $parameters)
    {
        $this->addClaim($method, $parameters[0]);

        return $this;
    }
}
