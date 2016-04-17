<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth;

use Countable;
use ArrayAccess;
use JsonSerializable;
use BadMethodCallException;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Tymon\JWTAuth\Claims\Claim;
use Illuminate\Support\Collection;
use Illuminate\Contracts\Support\Jsonable;
use Illuminate\Contracts\Support\Arrayable;
use Tymon\JWTAuth\Exceptions\PayloadException;
use Tymon\JWTAuth\Validators\PayloadValidator;

class Payload implements ArrayAccess, Arrayable, JsonSerializable, Jsonable, Countable
{
    /**
     * The collection of claims.
     *
     * @var \Illuminate\Support\Collection
     */
    private $claims;

    /**
     * Build the Payload.
     *
     * @param  \Illuminate\Support\Collection  $claims
     * @param  \Tymon\JWTAuth\Validators\PayloadValidator  $validator
     * @param  bool  $refreshFlow
     *
     * @return void
     */
    public function __construct(Collection $claims, PayloadValidator $validator, $refreshFlow = false)
    {
        $this->claims = $claims;

        $validator->setRefreshFlow($refreshFlow)->check($this->toArray());
    }

    /**
     * Get the array of claim instances.
     *
     * @return \Illuminate\Support\Collection
     */
    public function getClaims()
    {
        return $this->claims;
    }

    /**
     * Get the payload.
     *
     * @param  mixed  $claim
     *
     * @return mixed
     */
    public function get($claim = null)
    {
        $claim = value($claim);

        if ($claim !== null) {
            if (is_array($claim)) {
                return array_map([$this, 'get'], $claim);
            }

            return Arr::get($this->toArray(), $claim);
        }

        return $this->toArray();
    }

    /**
     * Determine whether the payload has the claim (by instance).
     *
     * @param  \Tymon\JWTAuth\Claims\Claim  $claim
     *
     * @return bool
     */
    public function has(Claim $claim)
    {
        return in_array($claim, $this->claims->toArray());
    }

    /**
     * Determine whether the payload has the claim (by key).
     *
     * @param  string  $claim
     *
     * @return bool
     */
    public function hasKey($claim)
    {
        return $this->offsetExists($claim);
    }

    /**
     * Get the array of claims.
     *
     * @return array
     */
    public function toArray()
    {
        $collection = $this->claims->map(function (Claim $claim) {
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
     *
     * @return string
     */
    public function toJson($options = JSON_UNESCAPED_SLASHES)
    {
        return json_encode($this->toArray(), $options);
    }

    /**
     * Get the payload as a string.
     *
     * @return string
     */
    public function __toString()
    {
        return $this->toJson();
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
        return Arr::has($this->toArray(), $key);
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
        return Arr::get($this->toArray(), $key);
    }

    /**
     * Don't allow changing the payload as it should be immutable.
     *
     * @param  mixed  $key
     * @param  mixed  $value
     *
     * @throws \Tymon\JWTAuth\Exceptions\PayloadException
     */
    public function offsetSet($key, $value)
    {
        throw new PayloadException('The payload is immutable');
    }

    /**
     * Don't allow changing the payload as it should be immutable.
     *
     * @param  string  $key
     *
     * @throws \Tymon\JWTAuth\Exceptions\PayloadException
     *
     * @return void
     */
    public function offsetUnset($key)
    {
        throw new PayloadException('The payload is immutable');
    }

    /**
     * Count the number of claims.
     *
     * @return int
     */
    public function count()
    {
        return count($this->toArray());
    }

    /**
     * Invoke the Payload as a callable function.
     *
     * @param  mixed  $claim
     *
     * @return mixed
     */
    public function __invoke($claim = null)
    {
        return $this->get($claim);
    }

    /**
     * Magically get a claim value.
     *
     * @param  string  $method
     * @param  array  $parameters
     *
     * @throws \BadMethodCallException
     *
     * @return mixed
     */
    public function __call($method, $parameters)
    {
        if (Str::startsWith($method, 'get')) {
            $class = sprintf('Tymon\\JWTAuth\\Claims\\%s', substr($method, 3));

            foreach ($this->claims as $claim) {
                if (get_class($claim) === $class) {
                    return $claim->getValue();
                }
            }
        }

        throw new BadMethodCallException(sprintf('The claim [%s] does not exist on the payload.', $method));
    }
}
