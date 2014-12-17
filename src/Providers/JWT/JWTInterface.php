<?php

namespace Tymon\JWTAuth\Providers\JWT;

interface JWTInterface
{
    /**
     * @param  mixed  $subject
     * @param  array  $customClaims
     * @return string
     */
    public function encode(array $payload);

    /**
     * @param  string  $token
     * @return array
     */
    public function decode($token);
}
