<?php

namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Payload;
use Tymon\JWTAuth\Claims\Factory;
use Illuminate\Http\Request;

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
        $this->buildClaims($customClaims);

        return new Payload($this->resolveClaims());
    }

    /**
     * Add an array of claims
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

    public function resolveClaims()
    {
        $resolved = [];
        foreach ($this->claims as $name => $value) {
            $resolved[] = $this->claimFactory->get($name, $value);
        }

        return $resolved;
    }

    /**
     * Create a unique id for the token
     *
     * @return string
     */
    protected function jti()
    {
        return md5('jti.'. $this->claims['sub'] . '.' . $this->claims['iat']);
    }

    public function iss()
    {
        return $this->request->url();
    }

    public function iat()
    {
        return time();
    }

    public function exp()
    {
        return time() + ($this->ttl * 60);
    }

    public function nbf()
    {
        return time();
    }

    /**
     * Magically set the claims
     *
     * @param  string  $method
     * @param  array   $parameters
     * @return this
     * @throws \BadMethodCallException
     */
    public function __call($method, $parameters)
    {
        $this->addClaim($method, $parameters[0]);

        return $this;
    }
}
