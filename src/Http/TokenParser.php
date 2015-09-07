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

class TokenParser
{
    /**
     * @var \Illuminate\Http\Request
     */
    protected $request;

    /**
     * The header name
     *
     * @var string
     */
    protected $header = 'authorization';

    /**
     * The header prefix
     *
     * @var string
     */
    protected $prefix = 'bearer';

    /**
     * The query string key
     *
     * @var string
     */
    protected $query = 'token';

    /**
     * @param \Illuminate\Http\Request $request
     */
    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    /**
     * Attempt to parse the token from some other possible headers
     *
     * @return false|string
     */
    protected function fromAltHeaders()
    {
        return $this->request->server->get('HTTP_AUTHORIZATION',
            $this->request->server->get('REDIRECT_HTTP_AUTHORIZATION', false)
        );
    }

    /**
     * Try to parse the token from the request header
     *
     * @return false|string
     */
    public function fromHeader()
    {
        $header = $this->request->headers->get($this->header, $this->fromAltHeaders());

        if (! $header || ! starts_with(strtolower($header), $this->prefix)) {
            return false;
        }

        return trim(str_ireplace($this->prefix, '', $header));
    }

    /**
     * Try to parse the token from the request query string
     *
     * @return false|string
     */
    public function fromQueryString()
    {
        return $this->request->input($this->query, false);
    }

    /**
     * Try to parse the token from either the header or query string
     *
     * @return false|string
     */
    public function parseToken()
    {
        return $this->fromHeader() ?: $this->fromQueryString();
    }

    /**
     * Check whether a token exists in the request
     *
     * @return  boolean
     */
    public function hasToken()
    {
        return $this->parseToken() !== false;
    }

    /**
     * Set the request instance.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return TokenParser
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;

        return $this;
    }

    /**
     * Set the header name
     *
     * @param  string  $headerName
     */
    public function setHeaderName($headerName)
    {
        $this->header = $headerName;

        return $this;
    }

    /**
     * Set the header prefix
     *
     * @param  string  $headerPrefix
     */
    public function setHeaderPrefix($headerPrefix)
    {
        $this->prefix = $headerPrefix;

        return $this;
    }

    /**
     * Set the query string
     *
     * @param  string  $quesryString
     */
    public function setQueryString($quesryString)
    {
        $this->query = $quesryString;

        return $this;
    }
}
