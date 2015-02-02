<?php

namespace Tymon\JWTAuth\Claims;

class Expiration extends Claim
{
    /**
     * The claim name
     *
     * @var string
     */
    protected $name = 'exp';

    /**
     * Validate the expiry claim
     *
     * @param  mixed  $value
     * @return boolean
     */
    protected function validate($value)
    {
        return is_numeric($value);
    }
}
