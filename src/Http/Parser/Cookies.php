<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Http\Parser;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Tymon\JWTAuth\Contracts\Http\Parser as ParserContract;

class Cookies implements ParserContract
{
    use KeyTrait;

    /**
     * Decrypt or not the cookie while parsing.
     *
     * @var bool
     */
    private $decrypt;

    public function __construct($decrypt = true)
    {
        $this->decrypt = $decrypt;
    }

    /**
     * Try to parse the token from the request cookies.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return null|string
     */
    public function parse(Request $request)
    {
        if ($this->decrypt && $request->hasCookie($this->key)) {
            return Crypt::decrypt($request->cookie($this->key));
        }

        return $request->cookie($this->key);
    }
}
