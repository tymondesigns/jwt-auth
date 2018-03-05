<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Validators;

use Tymon\JWTAuth\Claims\Collection;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class PayloadValidator extends Validator
{
    /**
     * The required claims.
     *
     * @var array
     */
    protected $requiredClaims = [
        'iss',
        'iat',
        'exp',
        'sub',
        'jti',
    ];

    /**
     * The refresh TTL.
     *
     * @var int
     */
    protected $refreshTTL = 20160;

    /**
     * Run the validations on the payload array.
     *
     * @param  \Tymon\JWTAuth\Claims\Collection  $value
     */
    public function check($value): Collection
    {
        $this->validateStructure($value);

        return $this->refreshFlow ? $this->validateRefresh($value) : $this->validatePayload($value);
    }

    /**
     * Ensure the payload contains the required claims and
     * the claims have the relevant type.
     *
     * @param  \Tymon\JWTAuth\Claims\Collection  $claims
     *
     * @throws \Tymon\JWTAuth\Exceptions\TokenInvalidException
     */
    protected function validateStructure(Collection $claims)
    {
        if (! $claims->hasAllClaims($this->requiredClaims)) {
            throw new TokenInvalidException('JWT payload does not contain the required claims');
        }
    }

    /**
     * Validate the payload timestamps.
     *
     * @throws \Tymon\JWTAuth\Exceptions\TokenExpiredException
     * @throws \Tymon\JWTAuth\Exceptions\TokenInvalidException
     */
    protected function validatePayload(Collection $claims): Collection
    {
        return $claims->validate('payload');
    }

    /**
     * Check the token in the refresh flow context.
     *
     * @throws \Tymon\JWTAuth\Exceptions\TokenExpiredException
     */
    protected function validateRefresh(Collection $claims): Collection
    {
        return $this->refreshTTL === null ? $claims : $claims->validate('refresh', $this->refreshTTL);
    }

    /**
     * Set the required claims.
     */
    public function setRequiredClaims(array $claims): self
    {
        $this->requiredClaims = $claims;

        return $this;
    }

    /**
     * Set the refresh ttl.
     *
     * @param  int|null  $ttl
     */
    public function setRefreshTTL($ttl): self
    {
        $this->refreshTTL = $ttl;

        return $this;
    }
}
