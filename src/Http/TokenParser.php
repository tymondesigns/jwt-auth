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
        return $this->request->query($this->query, false);
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
}
