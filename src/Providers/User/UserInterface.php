<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Providers\User;

interface UserInterface
{
    /**
     * Get the user by the given key, value.
     *
     * @param string $key
     * @param mixed $value
     * @return Illuminate\Database\Eloquent\Model|null
     */
    public function getBy($key, $value);
}
