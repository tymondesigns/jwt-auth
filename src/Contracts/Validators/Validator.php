<?php

namespace Tymon\JWTAuth\Contracts\Validators;

interface Validator
{
    /**
     * Perform some checks on the value
     *
     * @param  mixed  $value
     * @return void
     */
    public function check($value);

    /**
     * Helper function to return a boolean
     *
     * @param  array  $value
     * @return boolean
     */
    public function isValid($value);
}
