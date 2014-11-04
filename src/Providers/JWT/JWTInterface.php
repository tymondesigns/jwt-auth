<?php

namespace Tymon\JWTAuth\Providers\JWT;

interface JWTInterface
{
    /**
     * @param  mixed  $subject
     * @param  array  $customClaims
     * @return \Tymon\JWTAuth\Token
     */
    public function encode($subject, array $customClaims = []);

    /**
     * @param  string  $token
     * @return \Tymon\JWTAuth\Payload
     */
    public function decode($token);
}
