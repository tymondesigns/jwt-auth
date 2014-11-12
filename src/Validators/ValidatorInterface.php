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
}
