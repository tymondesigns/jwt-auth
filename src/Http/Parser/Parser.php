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

use Illuminate\Support\Arr;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Contracts\Http\Parser as ParserContract;

class Parser
{
    /**
     * The request.
     *
     * @var \Illuminate\Http\Request
     */
    protected $request;

    /**
     * The chain.
     *
     * @var array
     */
    private $chain;

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
     */
    public function setChain(array $chain): self
    {
        $this->chain = $chain;

        return $this;
    }

    /**
     * Alias for setting the order of the chain.
     */
    public function setChainOrder(array $chain): self
    {
        return $this->setChain($chain);
    }

    /**
     * Get a parser by key.
     */
    public function get(string $key): ?ParserContract
    {
        return Arr::get($this->chain, $key);
    }

    /**
     * Iterate through the parsers and attempt to retrieve
     * a value, otherwise return null.
     */
    public function parseToken(): ?string
    {
        foreach ($this->chain as $parser) {
            if ($token = $parser->parse($this->request)) {
                return $token;
            }
        }

        return null;
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
     */
    public function setRequest(Request $request): self
    {
        $this->request = $request;

        return $this;
    }

    /**
     * Get the request instance.
     */
    public function getRequest(): Request
    {
        return $this->request;
    }
}
