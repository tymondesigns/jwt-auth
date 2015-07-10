<?php

namespace Tymon\JWTAuth\Validators;

use Tymon\JWTAuth\Support\RefreshFlow;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Contracts\Validator as ValidatorContract;

abstract class Validator implements ValidatorContract
{
    use RefreshFlow;

    /**
     * Helper function to return a boolean
     *
     * @param  array  $value
     *
     * @return boolean
     */
    public function isValid($value)
    {
        try {
            $this->check($value);
        } catch (JWTException $e) {
            return false;
        }

        return true;
    }

    /**
     * Run the validation
     *
     * @param  array  $value
     *
     * @return void
     */
    abstract public function check($value);
}
