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

namespace Tymon\JWTAuth\Claims;

use JsonSerializable;
use Illuminate\Contracts\Support\Jsonable;
use Illuminate\Contracts\Support\Arrayable;
use Tymon\JWTAuth\Contracts\Claim as ClaimContract;

abstract class Claim implements Arrayable, ClaimContract, Jsonable, JsonSerializable
{
    /**
     * The claim name.
     *
     * @var string|null
     */
    protected $name;

    /**
     * The claim value.
     *
     * @var mixed
     */
    private $value;

    /**
     * Constructor.
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
     */
    public function setValue($value): ClaimContract
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
     */
    public function setName(string $name): ClaimContract
    {
        $this->name = $name;

        return $this;
    }

    /**
     * Get the claim name.
     */
    public function getName(): string
    {
        return $this->name ?? static::NAME;
    }

    /**
     * Validate the claim for creation.
     *
     * @param  mixed  $value
     *
     * @return mixed
     */
    public function validateCreate($value)
    {
        return $value;
    }

    /**
     * Check the claim when verifying the validity of the payload.
     */
    public function verify(): void
    {
        //
    }

    /**
     * Create an instance of the claim.
     */
    public static function make($value = null): ClaimContract
    {
        return new static($value);
    }

    /**
     * Checks if the value matches the claim.
     *
     * @param  mixed  $value
     */
    public function matches($value, bool $strict = true): bool
    {
        return $strict
            ? $this->value === $value
            : $this->value == $value;
    }

    /**
     * Checks if the name matches the claim.
     */
    public function matchesName(string $name): bool
    {
        return $this->getName() === $name;
    }

    /**
     * Convert the object into something JSON serializable.
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Build a key value array comprising of the claim name and value.
     */
    public function toArray(): array
    {
        return [$this->getName() => $this->getValue()];
    }

    /**
     * Get the claim as JSON.
     *
     * @param  int  $options
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
}
