<?php

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
     * Try to parse the token from the request header
     *
     * @return false|string
     */
    public function parseTokenFromHeader()
    {
        if ($this->request->server->has('HTTP_AUTHORIZATION')) {
            $this->request->headers->set($this->header, $this->request->server->get('HTTP_AUTHORIZATION'))
        } elseif ($this->request->server->has('REDIRECT_HTTP_AUTHORIZATION') {
            $this->request->headers->set($this->header, $this->request->server->get('REDIRECT_HTTP_AUTHORIZATION'))
        }

        $header = $this->request->headers->get($this->header);

        if (! starts_with(strtolower($this->header), $this->prefix)) {
            return false;
        }

        return trim(str_ireplace($this->prefix, '', $this->header));
    }

    /**
     * Try to parse the token from the request query string
     *
     * @return false|string
     */
    public function parseTokenFromQueryString()
    {
        return $this->request->query($this->query, false);
    }

    /**
     * Try to parse the token from either the header or query string
     *
     * @return false|string
     */
    public function parseToken()
    {
        if (! $token = $this->parseTokenFromHeader()) {
            if (! $token = $this->parseTokenFromQueryString()) {
                return false;
            }
        }

        return $token;
    }

    /**
     * Set the request instance.
     *
     * @param \Illuminate\Http\Request $request
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;

        return $this;
    }
}