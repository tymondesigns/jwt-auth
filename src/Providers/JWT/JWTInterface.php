<?php

namespace Tymon\JWTAuth\Providers\JWT;

interface JWTInterface
{
    /**
     * @param  array  $payload
     * @return string
     */
    public function encode(array $payload);

    /**
     * @param  string  $token
     * @return array
     */
    public function decode($token);
}
