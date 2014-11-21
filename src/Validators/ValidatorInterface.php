<?php

namespace Tymon\JWTAuth\Validators;

interface ValidatorInterface
{
    /**
     * Perform some checks on the value
     *
     * @param  mixed  $value
     * @return void
     */
    public static function check($value);
    
    /**
     * Helper function to return a boolean
     *
     * @param  array  $value
     * @return bool
     */
    public static function isValid($value);
}
