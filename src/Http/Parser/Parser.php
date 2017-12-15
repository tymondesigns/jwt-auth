<?php

declare(strict_types=1);

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

class Parser
{
    /**
     * The chain.
     *
     * @var array
     */
    private $chain;

    /**
     * The request.
     *
     * @var \Illuminate\Http\Request
     */
    protected $request;

    /**
     * Constructor.
     */
    public function __construct(Request $request, array $chain = [])
    {
        $this->request = $request;
        $this->chain = $chain;
    }

    /**
     * Get the parser chain.
     */
    public function getChain(): array
    {
        return $this->chain;
    }

    /**
     * Set the order of the parser chain.
     *
     * @return $this
     */
    public function setChain(array $chain)
    {
        $this->chain = $chain;

        return $this;
    }

    /**
     * Alias for setting the order of the chain.
     *
     * @return $this
     */
    public function setChainOrder(array $chain)
    {
        return $this->setChain($chain);
    }

    /**
     * Iterate through the parsers and attempt to retrieve
     * a value, otherwise return null.
     *
     * @return string|null
     */
    public function parseToken()
    {
        foreach ($this->chain as $parser) {
            if ($response = $parser->parse($this->request)) {
                return $response;
            }
        }
    }

    /**
     * Check whether a token exists in the chain.
     */
    public function hasToken(): bool
    {
        return $this->parseToken() !== null;
    }

    /**
     * Set the request instance.
     *
     * @return $this
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;

        return $this;
    }
}
