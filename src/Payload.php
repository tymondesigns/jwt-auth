<?php

declare(strict_types=1);

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
use Tymon\JWTAuth\Claims\Claim;
use Tymon\JWTAuth\Claims\Collection;
use Illuminate\Contracts\Support\Jsonable;
use Illuminate\Contracts\Support\Arrayable;
use Tymon\JWTAuth\Exceptions\PayloadException;

class Payload implements ArrayAccess, Arrayable, Countable, Jsonable, JsonSerializable
{
    /**
     * The collection of claims.
     *
     * @var \Tymon\JWTAuth\Claims\Collection
     */
    private $claims;

    /**
     * Constructor.
     */
    public function __construct(Collection $claims)
    {
        $this->claims = $claims;
    }

    /**
     * Get the collection of claim instances.
     */
    public function getClaims(): Collection
    {
        return $this->claims;
    }

    /**
     * Checks if a payload matches some expected values.
     */
    public function matches(array $values, bool $strict = false): bool
    {
        if (empty($values)) {
            return false;
        }

        $claims = $this->getClaims();

        foreach ($values as $key => $value) {
            if (! $claims->has($key) || ! $claims->get($key)->matches($value, $strict)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Checks if a payload strictly matches some expected values.
     */
    public function matchesStrict(array $values): bool
    {
        return $this->matches($values, true);
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
     * Get the underlying Claim instance.
     */
    public function getInternal(string $claim): Claim
    {
        return $this->claims->getByClaimName($claim);
    }

    /**
     * Determine whether the payload has the claim (by instance).
     */
    public function has(Claim $claim): bool
    {
        return $this->claims->has($claim->getName());
    }

    /**
     * Determine whether the payload has the claim (by key).
     */
    public function hasKey(string $claim): bool
    {
        return $this->offsetExists($claim);
    }

    /**
     * Get the array of claims.
     */
    public function toArray(): array
    {
        return $this->claims->toPlainArray();
    }

    /**
     * Convert the object into something JSON serializable.
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Get the payload as JSON.
     */
    public function toJson($options = JSON_UNESCAPED_SLASHES): string
    {
        return json_encode($this->toArray(), $options);
    }

    /**
     * Get the payload as a string.
     */
    public function __toString(): string
    {
        return $this->toJson();
    }

    /**
     * Determine if an item exists at an offset.
     *
     * @param  mixed  $key
     */
    public function offsetExists($key): bool
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
        throw new PayloadException();
    }

    /**
     * Don't allow changing the payload as it should be immutable.
     *
     * @param  mixed  $key
     *
     * @throws \Tymon\JWTAuth\Exceptions\PayloadException
     */
    public function offsetUnset($key)
    {
        throw new PayloadException();
    }

    /**
     * Count the number of claims.
     */
    public function count(): int
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
     * @throws \BadMethodCallException
     *
     * @return mixed
     */
    public function __call(string $method, array $parameters)
    {
        if (preg_match('/get(.+)\b/i', $method, $matches)) {
            foreach ($this->claims as $claim) {
                if (get_class($claim) === 'Tymon\\JWTAuth\\Claims\\'.$matches[1]) {
                    return $claim->getValue();
                }
            }
        }

        throw new BadMethodCallException(sprintf('The claim [%s] does not exist on the payload.', $method));
    }
}
