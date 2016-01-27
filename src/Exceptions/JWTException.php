<?php

/*
 * This file is part of jwt-auth
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Exceptions;

use Exception;

class JWTException extends Exception
{
    /**
     * @param string  $message
     */
    public function __construct($message = 'An error occurred')
    {
        parent::__construct($message);
    }
}
