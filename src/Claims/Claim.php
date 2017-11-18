<?php declare(strict_types=1);

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Claims;

use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\Jsonable;
use JsonSerializable;
use Tymon\JWTAuth\Contracts\Claim as ClaimContract;

abstract class Claim implements Arrayable, ClaimContract, Jsonable, JsonSerializable
{
    /**
     * The claim name.
     *
     * @var string
     */
    protected $name;

    /**
     * The claim value.
     *
     * @var mixed
     */
    private $value;

    /**
     * @param  mixed  $value
     *
     */
    public function __construct($value)
    {
        $this->setValue($value);
    }

    /**
     * Set the claim value, and call a validate method.
     *
     * @param  mixed  $value
     *
     * @throws \Tymon\JWTAuth\Exceptions\InvalidClaimException
     *
     * @return $this
     */
    public function setValue($value)
    {
        $this->value = $this->validateCreate($value);

        return $this;
    }

    /**
     * Get the claim value.
     *
     * @return mixed
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * Set the claim name.
     *
     * @param  string  $name
     *
     * @return $this
     */
    public function setName(string $name)
    {
        $this->name = $name;

        return $this;
    }

    /**
     * Get the claim name.
     *
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Validate the claim in a standalone Claim context.
     *
     * @param  mixed  $value
     *
     * @return bool
     */
    public function validateCreate($value)
    {
        return $value;
    }

    /**
     * Validate the Claim within a Payload context.
     *
     * @return bool
     */
    public function validatePayload()
    {
        return $this->getValue();
    }

    /**
     * Validate the Claim within a refresh context.
     *
     * @param  int  $refreshTTL
     *
     * @return bool
     */
    public function validateRefresh()
    {
        return $this->getValue();
    }

    /**
     * Checks if the value matches the claim.
     *
     * @param  mixed  $value
     * @param  bool  $strict
     *
     */
    public function matches($value, $strict = true): bool
    {
        return $strict ? $this->value === $value : $this->value == $value;
    }

    /**
     * Convert the object into something JSON serializable.
     *
     * @return array
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Build a key value array comprising of the claim name and value.
     *
     * @return array
     */
    public function toArray(): array
    {
        return [$this->getName() => $this->getValue()];
    }

    /**
     * Get the claim as JSON.
     */
    public function toJson(int $options = JSON_UNESCAPED_SLASHES): string
    {
        return json_encode($this->toArray(), $options);
    }

    /**
     * Get the payload as a string.
     *
     */
    public function __toString(): string
    {
        return $this->toJson();
    }
}
