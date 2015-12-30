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

class Parser
{
    /**
     * @var array
     */
    private $chain = [];

    /**
     * @var \Illuminate\Http\Request
     */
    protected $request;

    /**
     * @param \Illuminate\Http\Request $request
     */
    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    /**
     * Set the order of the parser chain
     *
     * @param  array  $chain
     */
    public function setChainOrder(array $chain)
    {
        $this->chain = $chain;

        return $this;
    }

    /**
     * Iterate throught the parsers and attempt to retrieve
     * a value, otherwise return null
     *
     * @return string|null
     */
    public function parseToken()
    {
        foreach ($this->chain as $parser) {
            $response = $parser->parse($this->request);

            if ($response !== null) {
                return $response;
            }
        }

        return null;
    }

    /**
     * Check whether a token exists in the chain
     *
     * @return  boolean
     */
    public function hasToken()
    {
        return $this->parseToken() !== null;
    }

    /**
     * Set the request instance.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return Parser
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;

        return $this;
    }
}
