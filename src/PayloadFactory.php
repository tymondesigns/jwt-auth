<?php

namespace Tymon\JWTAuth;

use Illuminate\Http\Request;
use Tymon\JWTAuth\RefreshFlow;
use Tymon\JWTAuth\Claims\Factory;
use Illuminate\Support\Collection;
use Tymon\JWTAuth\Validators\PayloadValidator;

class PayloadFactory
{
    use RefreshFlow;

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
     * @var array
     */
    protected $defaultClaims = ['iss', 'iat', 'exp', 'nbf', 'jti'];

    /**
     * Custom claims
     *
     * @var array
     */
    protected $customClaims = [];

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
     * @param null $claims
     *
     * @return \Tymon\JWTAuth\Payload
     */
    public function make($claims = null)
    {
        $claims = $claims ? $this->addClaims($claims)->resolveClaims() : $this->buildClaims($claims)->resolveClaims();

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
     * @return PayloadFactory
     */
    protected function buildClaims()
    {
        // add any custom claims first
        $this->addClaims(array_diff_key($this->customClaims, $this->defaultClaims));

        // add the default claims
        foreach ($this->defaultClaims as $claim) {
            if (! array_key_exists($claim, $this->customClaims)) {
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
    protected function resolveClaims()
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
        return (int) Utils::now()->format('U');
    }

    /**
     * Get the Expiration (exp) claim
     *
     * @return int
     */
    public function exp()
    {
        return (int) Utils::now()->addMinutes($this->ttl)->format('U');
    }

    /**
     * Get the Not Before (nbf) claim
     *
     * @return int
     */
    public function nbf()
    {
        return (int) Utils::now()->format('U');
    }

    /**
     * Get a unique id (jti) for the token
     *
     * @return string
     */
    protected function jti()
    {
        return md5(sprintf('%s.%s', $this->claims->toJson(), str_random()));
    }

    /**
     * Set the custom claims.
     *
     * @param array $customClaims
     *
     * @return $this
     */
    public function customClaims(array $customClaims = [])
    {
        $this->customClaims = $customClaims;

        return $this;
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
