<?php

namespace Tymon\JWTAuth\Validators;

use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class PayloadValidator extends AbstractValidator
{
    /**
     * @var array
     */
    protected $requiredClaims = ['iss', 'iat', 'exp', 'nbf', 'sub', 'jti'];

    /**
     * Run the validations on the payload array
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
     * the claims have the relevant type
     *
     * @param array $payload
     * @throws \Tymon\JWTAuth\Exceptions\TokenInvalidException
     * @return bool
     */
    protected function validateStructure(array $payload)
    {
        if (count(array_diff($this->requiredClaims, array_keys($payload))) !== 0) {
            throw new TokenInvalidException('JWT payload does not contain the required claims');
        }

        return true;
    }

    /**
     * Validate the payload timestamps
     *
     * @param  array  $payload
     * @throws \Tymon\JWTAuth\Exceptions\TokenExpiredException
     * @throws \Tymon\JWTAuth\Exceptions\TokenInvalidException
     * @return boolean
     */
    protected function validateTimestamps(array $payload)
    {
        if ($this->carbon($payload['nbf'])->isFuture()) {
            throw new TokenInvalidException('Not Before (nbf) timestamp cannot be in the future');
        }

        if ($this->carbon($payload['iat'])->isFuture()) {
            throw new TokenInvalidException('Issued At (iat) timestamp cannot be in the future');
        }

        if ($this->carbon($payload['exp'])->isPast()) {
            throw new TokenExpiredException('Token has expired');
        }

        return true;
    }

    /**
     * Check the token in the refresh flow context
     *
     * @param  $payload
     * @return bool
     */
    protected function validateRefresh(array $payload)
    {
        // @todo check the issued at timestamp and limit to longer time e.g. 2 weeks
        // so the user will need to re-login at least every 2 weeks.

        return true;
    }
}
