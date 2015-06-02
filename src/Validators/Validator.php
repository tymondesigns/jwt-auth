<?php

namespace Tymon\JWTAuth\Validators;

use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Contracts\Validators\Validator as ValidatorContract;

abstract class Validator implements ValidatorContract
{
    /**
     * @var bool
     */
    protected $refreshFlow = false;

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
     * Set the refresh flow flag
     *
     * @param  boolean  $refreshFlow
     *
     * @return $this
     */
    public function setRefreshFlow($refreshFlow = true)
    {
        $this->refreshFlow = $refreshFlow;

        return $this;
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
