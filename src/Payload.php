<?php

namespace Tymon\JWTAuth;

use ArrayAccess;
use JsonSerializable;
use Countable;
use Tymon\JWTAuth\Claims\Claim;
use Illuminate\Support\Collection;
use Illuminate\Contracts\Support\Jsonable;
use Illuminate\Contracts\Support\Arrayable;
use Tymon\JWTAuth\Exceptions\PayloadException;
use Tymon\JWTAuth\Validators\PayloadValidator;

class Payload implements ArrayAccess, Arrayable, JsonSerializable, Jsonable, Countable
{
    /**
     * The collection of claims
     *
     * @var \Illuminate\Support\Collection
     */
    private $claims;

    /**
     * Build the Payload
     *
     * @param \Illuminate\Support\Collection              $claims
     * @param \Tymon\JWTAuth\Validators\PayloadValidator  $validator
     * @param boolean                                     $refreshFlow
     */
    public function __construct(Collection $claims, PayloadValidator $validator, $refreshFlow = false)
    {
        $this->claims = $claims;

        $validator->setRefreshFlow($refreshFlow)->check($this->toArray());
    }

    /**
     * Get the array of claim instances
     *
     * @return \Illuminate\Support\Collection
     */
    public function getClaims()
    {
        return $this->claims;
    }

    /**
     * Get the payload
     *
     * @param  mixed  $claim
     *
     * @return mixed
     */
    public function get($claim = null)
    {
        if (! is_null($claim)) {
            if (is_array($claim)) {
                return array_map([$this, 'get'], $claim);
            }

            return array_get($this->toArray(), $claim, false);
        }

        return $this->toArray();
    }

    /**
     * Determine whether the payload has the claim
     *
     * @param  \Tymon\JWTAuth\Claims\Claim  $claim
     *
     * @return boolean
     */
    public function has(Claim $claim)
    {
        return in_array($claim, $this->claims->toArray());
    }

    /**
     * Get the array of claims
     *
     * @return array
     */
    public function toArray()
    {
        $collection = $this->claims->map(function ($claim) {
            return $claim->getValue();
        });

        return $collection->toArray();
    }

    /**
     * Convert the object into something JSON serializable.
     *
     * @return array
     */
    public function jsonSerialize()
    {
        return $this->toArray();
    }

    /**
     * Get the payload as JSON.
     *
     * @param  int  $options
     * @return string
     */
    public function toJson($options = 0)
    {
        return json_encode($this->toArray(), $options);
    }

    /**
     * Get the payload as a string
     *
     * @return string
     */
    public function __toString()
    {
        return $this->toJson(JSON_UNESCAPED_SLASHES);
    }

    /**
     * Determine if an item exists at an offset.
     *
     * @param  mixed  $key
     *
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
     *
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
     *
     * @throws Exceptions\PayloadException
     */
    public function offsetSet($key, $value)
    {
        throw new PayloadException('The payload is immutable');
    }

    /**
     * Don't allow changing the payload as it should be immutable
     *
     * @param  string  $key
     *
     * @throws Exceptions\PayloadException
     */
    public function offsetUnset($key)
    {
        throw new PayloadException('The payload is immutable');
    }

    /**
     * Count the number of claims
     *
     * @return int
     */
    public function count()
    {
        return count($this->toArray());
    }

    /**
     * Magically get a claim value
     *
     * @param  string  $method
     * @param  array   $parameters
     *
     * @return mixed
     *
     * @throws \BadMethodCallException
     */
    public function __call($method, $parameters)
    {
        if (! method_exists($this, $method) && starts_with($method, 'get')) {
            $class = sprintf('Tymon\\JWTAuth\\Claims\\%s', substr($method, 3));

            foreach ($this->claims as $claim) {
                if (get_class($claim) === $class) {
                    return $claim->getValue();
                }
            }
        }

        throw new \BadMethodCallException(sprintf('The claim [%s] does not exist on the payload.', $method));
    }
}
