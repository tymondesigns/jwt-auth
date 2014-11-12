<?php

namespace Tymon\JWTAuth\Validators;

use Tymon\JWTAuth\Exceptions\JWTException;

abstract class AbstractValidator
{

    /**
     * Helper function to return a boolean
     *
     * @param  array  $value
     * @return bool
     */
    public static function isValid($value)
    {
        try {
            static::check($value);
        } catch (JWTException $e) {
            return false;
        }

        return true;
    }

    abstract public static function check($value);
}
