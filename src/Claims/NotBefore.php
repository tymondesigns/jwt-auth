<?php

namespace Tymon\JWTAuth\Claims;

class NotBefore extends Claim
{
    /**
     * The claim name
     *
     * @var string
     */
    protected $name = 'nbf';

    /**
     * Validate the not before claim
     *
     * @param  mixed  $value
     * @return boolean
     */
    protected function validate($value)
    {
        return is_numeric($value);
    }
}
