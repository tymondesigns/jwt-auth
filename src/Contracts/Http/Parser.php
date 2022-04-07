<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Contracts\Http;

use Illuminate\Http\Request;

interface Parser
{
    /**
     * Parse the request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return null|string
     */
    public function parse(Request $request);
}
