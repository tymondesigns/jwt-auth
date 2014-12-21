<?php

namespace Tymon\JWTAuth;

use ArrayAccess;
use Tymon\JWTAuth\Claims\Claim;
use Tymon\JWTAuth\Exceptions\PayloadException;

class Payload implements ArrayAccess
{

    /**
     * The array of claims
     *
     * @var array \Tymon\JWTAuth\Claims\Claim[]
     */
    private $claims = [];

    /**
     * Build the Payload
     *
     * @param array  $claims
     */
    public function __construct(array $claims)
    {
        $this->claims = $claims;
    }

    /**
     * Get the array of claim instances
     *
     * @return \Tymon\JWTAuth\Claims\Claim[]
     */
    public function getClaims()
    {
        return $this->claims;
    }

    /**
     * Get the array of claims
     *
     * @return array
     */
    public function toArray()
    {
        $results = [];
        foreach ($this->claims as $claim) {
            $results[$claim->getName()] = $claim->getValue();
        }

        return $results;
    }

    /**
     * Get the payload
     *
     * @param  string  $claim
     * @return array
     */
    public function get($claim = null)
    {
        if (! is_null($claim)) {

            if (is_array($claim)) {
                return array_map([$this, 'get'], $claim);
            }

            return array_get($this->toArray(), $claim);
        }

        return $this->toArray();
    }

    /**
     * Determine whether the payload has the claim
     *
     * @param  \Tymon\JWTAuth\Claims\Claim  $claim
     * @return boolean
     */
    public function has(Claim $claim)
    {
        return in_array($claim, $this->claims);
    }

    /**
     * Get the payload as a string
     *
     * @return string
     */
    public function __toString()
    {
        return json_encode($this->toArray());
    }

    /**
     * Determine if an item exists at an offset.
     *
     * @param  mixed  $key
     * @return bool
     */
    public function offsetExists($key)
    {
        return array_key_exists($key, $this->toArray());
    }

    /**
     * Get an item at a given offset.
     *
     * @param  mixed  $key
     * @return mixed
     */
    public function offsetGet($key)
    {
        return array_get($this->toArray(), $key, []);
    }

    /**
     * Don't allow changing the payload as it should be immutable
     *
     * @param  mixed  $key
     * @param  mixed  $value
     * @return void
     */
    public function offsetSet($key, $value)
    {
        throw new PayloadException('The payload is immutable');
    }

    /**
     * Don't allow changing the payload as it should be immutable
     *
     * @param  string  $key
     * @return void
     */
    public function offsetUnset($key)
    {
        throw new PayloadException('The payload is immutable');
    }

    /**
     * Magically get a claim value
     *
     * @param  string  $method
     * @param  array   $parameters
     * @return mixed
     * @throws \BadMethodCallException
     */
    public function __call($method, $parameters)
    {
        if (! method_exists($this, $method) && starts_with($method, 'get'))
        {
            $class = "Tymon\\JWTAuth\\Claims\\" . substr($method, 3);

            foreach ($this->claims as $claim) {
                if (get_class($claim) === $class) {
                    return $claim->getValue();
                }
            }
        }

        throw new \BadMethodCallException("The claim [$method] does not exist on the payload.");
    }
}
