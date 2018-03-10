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

namespace Tymon\JWTAuth\Contracts;

interface Claim
{
    /**
     * Set the claim value, and call a validate method.
     *
     * @param  mixed  $value
     *
     * @throws \Tymon\JWTAuth\Exceptions\InvalidClaimException
     */
    public function setValue($value): self;

    /**
     * Get the claim value.
     *
     * @return mixed
     */
    public function getValue();

    /**
     * Set the claim name.
     */
    public function setName(string $name): self;

    /**
     * Get the claim name.
     */
    public function getName(): string;

    /**
     * Validate the Claim value.
     *
     * @param  mixed  $value
     *
     * @return mixed
     */
    public function validateCreate($value);
}
