<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Exceptions;

class TokenExpiredException extends JWTException
{
    /**
     * @param  string  $message default: 'Token Expired'
     * @param  int  $code default: 498
     * @param  \Exception|null  $previous default: null
     *
     * @return void
     */
    public function __construct($message = 'Token Expired', $code = 498, Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }

}
