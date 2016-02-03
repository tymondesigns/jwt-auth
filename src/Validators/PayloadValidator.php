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

use Tymon\JWTAuth\Utils;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class PayloadValidator extends AbstractValidator
{
    /**
     * @var array
     */
    protected $requiredClaims = ['iss', 'iat', 'exp', 'nbf', 'sub', 'jti'];

    /**
     * @var int
     */
    protected $refreshTTL = 20160;

    /**
     * Run the validations on the payload array.
     *
     * @param  array  $value
     * @return void
     */
    public function check($value)
    {
        $this->validateStructure($value);

        if (! $this->refreshFlow) {
            $this->validateTimestamps($value);
        } else {
            $this->validateRefresh($value);
        }
    }

    /**
     * Ensure the payload contains the required claims and
     * the claims have the relevant type.
     *
     * @param array  $payload
     * @throws \Tymon\JWTAuth\Exceptions\TokenInvalidException
     * @return bool
     */
    protected function validateStructure(array $payload)
    {
        if (count(array_diff_key($this->requiredClaims, array_keys($payload))) !== 0) {
            throw new TokenInvalidException('JWT payload does not contain the required claims');
        }

        return true;
    }

    /**
     * Validate the payload timestamps.
     *
     * @param  array  $payload
     * @throws \Tymon\JWTAuth\Exceptions\TokenExpiredException
     * @throws \Tymon\JWTAuth\Exceptions\TokenInvalidException
     * @return bool
     */
    protected function validateTimestamps(array $payload)
    {
        if (isset($payload['nbf']) && Utils::timestamp($payload['nbf'])->isFuture()) {
            throw new TokenInvalidException('Not Before (nbf) timestamp cannot be in the future', 400);
        }

        if (isset($payload['iat']) && Utils::timestamp($payload['iat'])->isFuture()) {
            throw new TokenInvalidException('Issued At (iat) timestamp cannot be in the future', 400);
        }

        if (Utils::timestamp($payload['exp'])->isPast()) {
            throw new TokenExpiredException('Token has expired');
        }

        return true;
    }

    /**
     * Check the token in the refresh flow context.
     *
     * @param  $payload
     * @return bool
     */
    protected function validateRefresh(array $payload)
    {
        if (isset($payload['iat']) && Utils::timestamp($payload['iat'])->addMinutes($this->refreshTTL)->isPast()) {
            throw new TokenExpiredException('Token has expired and can no longer be refreshed', 400);
        }

        return true;
    }

    /**
     * Set the required claims.
     *
     * @param array  $claims
     */
    public function setRequiredClaims(array $claims)
    {
        $this->requiredClaims = $claims;

        return $this;
    }

    /**
     * Set the refresh ttl.
     *
     * @param int  $ttl
     */
    public function setRefreshTTL($ttl)
    {
        $this->refreshTTL = $ttl;

        return $this;
    }
}
