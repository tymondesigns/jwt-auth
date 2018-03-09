<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Validators;

use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Contracts\Validator as ValidatorContract;

abstract class Validator implements ValidatorContract
{
    /**
     * Helper function to return a boolean.
     *
     * @param  mixed  $value
     */
    public static function isValid($value): bool
    {
        try {
            static::check($value);
        } catch (JWTException $e) {
            return false;
        }
    }

    /**
     * Run the validation.
     *
     * @param  mixed  $value
     */
    abstract public static function check($value);
}
