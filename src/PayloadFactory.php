<?php

namespace Tymon\JWTAuth;

use Illuminate\Http\Request;
use Tymon\JWTAuth\Claims\Factory;
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
     * @var array
     */
    protected $claims = [];

    /**
     * @param \Tymon\JWTAuth\Claims\Factory  $claimFactory
     * @param \Illuminate\Http\Request  $request
     * @param \Tymon\JWTAuth\Validators\PayloadValidator  $validator
     */
    public function __construct(Factory $claimFactory, Request $request, PayloadValidator $validator)
    {
        $this->claimFactory = $claimFactory;
        $this->request = $request;
        $this->validator = $validator;
    }

    /**
     * Create the Payload instance
     *
     * @param  array  $customClaims
     * @param  mixed  $user
     * @return \Tymon\JWTAuth\Payload
     */
    public function make(array $customClaims = [], $user = null)
    {
        $claims = $this->buildClaims($customClaims, $user)->resolveClaims();

        return new Payload($claims, $this->validator, $this->refreshFlow);
    }

    /**
     * Add an array of claims to the Payload
     *
     * @param  array  $claims
     * @param  mixed  $user
     * @return $this
     */
    public function addClaims(array $claims, $user = null)
    {
        foreach ($claims as $name => $value) {
            $this->addClaim($name, $value, $user);
        }

        return $this;
    }

    /**
     * Add a claim to the Payload
     *
     * @param  string  $name
     * @param  mixed   $value
     * @param  mixed   $user
     * @return $this
     */
    public function addClaim($name, $value, $user = null)
    {
        if ($value instanceof \Closure || is_callable($value)) {
            $value = $value($user);
        }

        $this->claims[$name] = $value;

        return $this;
    }

    /**
     * Build the default claims
     *
     * @param  array  $customClaims
     * @param  mixed  $user
     * @return $this
     */
    protected function buildClaims(array $customClaims, $user = null)
    {
        // add any custom claims first
        $this->addClaims(array_diff_key($customClaims, $this->defaultClaims), $user);

        foreach ($this->defaultClaims as $claim) {
            if (! array_key_exists($claim, $customClaims)) {
                $this->addClaim($claim, $this->$claim(), $user);
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
        return Utils::now()->format('U');
    }

    /**
     * Set the Expiration (exp) claim
     *
     * @return int
     */
    public function exp()
    {
        return Utils::now()->addMinutes($this->ttl)->format('U');
    }

    /**
     * Set the Not Before (nbf) claim
     *
     * @return int
     */
    public function nbf()
    {
        return Utils::now()->format('U');
    }

    /**
     * Set a unique id (jti) for the token
     *
     * @return string
     */
    protected function jti()
    {
        $sub = array_get($this->claims, 'sub', '');
        $nbf = array_get($this->claims, 'nbf', '');

        return md5(sprintf('jti.%s.%s', $sub, $nbf));
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
