<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Contracts;

interface Validator
{
    /**
     * Perform some checks on the value.
     *
     * @param  mixed  $value
     * @return void
     */
    public function check($value);

    /**
     * Helper function to return a boolean.
     *
     * @param  array  $value
     * @return bool
     */
    public function isValid($value);
}
