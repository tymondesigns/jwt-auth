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

namespace Tymon\JWTAuth\Facades;

use Illuminate\Support\Facades\Facade;

class JWTFactory extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'tymon.jwt.payload.factory';
    }
}
