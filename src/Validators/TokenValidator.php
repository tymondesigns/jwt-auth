<?php

namespace Tymon\JWTAuth\Validators;

use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class TokenValidator extends AbstractValidator
{
    /**
     * Check the structure of the token
     *
     * @param string  $value
     * @return void
     */
    public function check($value)
    {
        $this->validateStructure($value);
    }

    /**
     * @param  string  $token
     * @throws \Tymon\JWTAuth\Exceptions\TokenInvalidException
     * @return boolean
     */
    protected function validateStructure($token)
    {
        if (count(explode('.', $token)) !== 3) {
            throw new TokenInvalidException('Wrong number of segments');
        }

        return true;
    }
}
