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

namespace Tymon\JWTAuth\Contracts\Http;

use Illuminate\Http\Request;

interface Parser
{
    /**
     * Parse the request.
     *
     * @param  \Illuminate\Http\Request $request
     *
     * @return  null|string
     */
    public function parse(Request $request);
}
