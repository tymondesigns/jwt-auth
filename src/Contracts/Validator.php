<?php

/*
 * This file is part of jwt-auth.
 *
 * @package tymon/jwt-auth
 * @author Sean Tymon <tymon148@gmail.com>
 * @copyright Copyright (c) Sean Tymon
 * @link https://github.com/tymondesigns/jwt-auth
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
