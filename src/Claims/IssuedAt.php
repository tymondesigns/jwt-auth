<?php

namespace Tymon\JWTAuth\Claims;

class IssuedAt extends Claim
{

    /**
     * The claim type
     *
     * @var string
     */
    protected $type = 'iat';

    /**
     * Whether the claim is required
     *
     * @var boolean
     */
    protected $required = true;

    /**
     * Validate the issued at claim
     *
     * @param  mixed  $value
     * @return boolean
     */
    protected function validate($value)
    {
        return is_int($value);
    }
}