<?php

namespace Tymon\JWTAuth;

use ArrayAccess;
use Tymon\JWTAuth\Exceptions\PayloadException;
use Tymon\JWTAuth\Validators\PayloadValidator;

class Payload implements ArrayAccess
{

    /**
     * @var array
     */
    protected $value;

    /**
     * Create a new JWT payload
     *
     * @param array $value
     */
    public function __construct(array $value)
    {
        PayloadValidator::check($value);

        $this->value = $value;
    }

    /**
     * Get the payload
     *
     * @param  string $property
     * @return array
     */
    public function get($property = null)
    {
        if (! is_null($property)) {
            return $this->value[$property];
        }

        return $this->value;
    }

    /**
     * Get the payload as a string
     *
     * @return string
     */
    public function __toString()
    {
        return json_encode($this->value);
    }

    /**
     * Determine if an item exists at an offset.
     *
     * @param  mixed $key
     * @return bool
     */
    public function offsetExists($key)
    {
        return array_key_exists($key, $this->value);
    }

    /**
     * Get an item at a given offset.
     *
     * @param  mixed $key
     * @return mixed
     */
    public function offsetGet($key)
    {
        return $this->value[$key];
    }

    /**
     * Don't allow changing the payload as it should be immutable
     *
     * @param  mixed $key
     * @param  mixed $value
     * @return void
     */
    public function offsetSet($key, $value)
    {
        throw new PayloadException('You cannot change the payload');
    }

    /**
     * Don't allow changing the payload as it should be immutable
     *
     * @param  string $key
     * @return void
     */
    public function offsetUnset($key)
    {
        throw new PayloadException('You cannot change the payload');
    }
}
