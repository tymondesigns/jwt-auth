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
     * Attempt to parse the token from some other possible headers
     *
     * @return false|string
     */
    protected function parseFromAltHeaders()
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
    public function parseTokenFromHeader()
    {
        $header = $this->request->headers->get($this->header, $this->parseFromAltHeaders());

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
        return $this->parseTokenFromHeader() ?: $this->parseTokenFromQueryString();
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