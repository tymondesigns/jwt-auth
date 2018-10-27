<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Claims;

use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Contracts\Auth\Authenticatable;

trait JwtAuthentication
{
    /**
     * Overrides the default actingAs() method to set the user token when
     * testing in Laravel.
     *
     * @param Authenticatable $user
     * @param null|string $driver
     *
     * @return $this
     */
    public function actingAs(Authenticatable $user, $driver = null)
    {
        if (method_exists($this, 'withHeader')) {
            $token = JWTAuth::fromUser($user);
            $this->withHeader('Authorization', 'Bearer '.$token);
        }

        return $this;
    }
}
