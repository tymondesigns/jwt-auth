<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Events;

abstract class AbstractJWTEvent
{
    /**
     * The authenticated user.
     *
     * @var \Illuminate\Contracts\Auth\Authenticatable
     */
    public $user;

    /**
     * @var \Tymon\JWTAuth\Token
     */
    public $token;

    /**
     * Create a new event instance.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  \Tymon\JWTAuth\Token|string  $token
     *
     * @return void
     */
    public function __construct($user, $token)
    {
        $this->token = $token;
        $this->user = $user;
    }
}
