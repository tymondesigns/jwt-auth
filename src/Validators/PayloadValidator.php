<?php

namespace Tymon\JWTAuth\Validators;

use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class PayloadValidator extends AbstractValidator
{
    /**
     * @var array
     */
    protected $requiredClaims = ['iss', 'iat', 'exp', 'sub', 'jti'];

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
            $this->validateExpiry($value);
        } else {
            $this->validateRefresh($value);
        }
    }

    /**
     * Ensure the payload contains the required claims and
     * the claims have the relevant type
     *
     * @param  $payload
     * @return bool
     */
    protected function validateStructure(array $payload)
    {
        if (count(array_diff($this->requiredClaims, array_keys($payload))) !== 0) {
            throw new TokenInvalidException('JWT payload does not contain the required claims');
        }

        if (! is_int($payload['iat'])) {
            throw new TokenInvalidException('Invalid Issued At (iat) provided');
        }

        if (! is_int($payload['exp'])) {
            throw new TokenInvalidException('Invalid Expiration (exp) provided');
        }

        return true;
    }

    /**
     * Validate the issue and expiry date of the payload
     *
     * @param  $payload
     * @return bool
     */
    protected function validateExpiry(array $payload)
    {
        if ($payload['iat'] > time() || $payload['exp'] < time()) {
            throw new TokenExpiredException('JWT has expired');
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
