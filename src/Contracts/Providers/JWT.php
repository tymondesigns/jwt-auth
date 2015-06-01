<?php

namespace Tymon\JWTAuth\Contracts\Providers;

interface JWT
{
    /**
     * @param  array  $payload
     *
     * @return string
     */
    public function encode(array $payload);

    /**
     * @param  string  $token
     *
     * @return array
     */
    public function decode($token);
}
