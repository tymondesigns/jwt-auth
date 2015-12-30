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

use Illuminate\Http\Request;
use Illuminate\Contracts\Http\Parser as ParserContract;

class RouteParams implements ParserContract
{

    /**
     * The route param key
     *
     * @var string
     */
    protected $key = 'token';

    /**
     * Try to get the token from the route parameters
     *
     * @param  \Illuminate\Http\Request
     *
     * @return null|string
     */
    public function parse(Request $request)
    {
        return $request->route()->parameter($this->key);
    }

    /**
     * Set the query string key
     *
     * @param  string  $key
     *
     * @return RouteParams
     */
    public function setKey($key)
    {
        $this->key = $key;

        return $this;
    }
}
