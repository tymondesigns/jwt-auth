<?php

/*
 * This file is part of jwt-auth
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Http;

use Illuminate\Support\Arr;
use Illuminate\Http\Request;

class LumenRouteParams extends RouteParams
{
    /**
     * Try to get the token from the route parameters
     *
     * @param  \Illuminate\Http\Request
     *
     * @return null|string
     */
    public function parse(Request $request)
    {
        // WARNING: Only use this parser if you know what you're doing!
        // It will only work with poorly-specified aspects of certain Lumen releases.
        $route = $request->route();

        if (! is_array($route) || ! Arr::has($route, '2.'.$this->key)) {
            // Route is not the expected kind of array, or does not have a parameter
            // with the key we want.
            return null;
        }

        return $route[2][$this->key];
    }
}
