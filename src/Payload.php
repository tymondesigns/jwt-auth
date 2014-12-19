<?php

namespace Tymon\JWTAuth;

use ArrayAccess;
use Tymon\JWTAuth\Exceptions\PayloadException;
use Tymon\JWTAuth\Claims\Claim;
use Tymon\JWTAuth\Driver;
use Tymon\JWTAuth\Token;
use Tymon\JWTAuth\Providers\JWT\FirebaseAdapter;

class Payload implements ArrayAccess
{

    use Driver;

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
     * Create the token from the payload
     *
     * @return \Tymon\JWTAuth\Token
     */
    public function token()
    {
        return new Token($this->encode());
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
        throw new PayloadException('You cannot change the payload');
    }

    /**
     * Don't allow changing the payload as it should be immutable
     *
     * @param  string  $key
     * @return void
     */
    public function offsetUnset($key)
    {
        throw new PayloadException('You cannot change the payload');
    }

    /**
     * Magically call the claims array
     *
     * @param  string  $method
     * @param  array   $parameters
     * @return mixed
     * @throws \BadMethodCallException
     */
    public function __call($method, $parameters)
    {
        if (starts_with($method, 'get'))
        {
            $instance = array_where(function (Claim $claim) use ($method) {
                return get_class($claim) === substr($method, 3);
            }, $this->claims);

            if ($instance) {
                return $instance->getValue();
            }
        }

        throw new \BadMethodCallException("The method [$method] does not exist.");
    }
}
