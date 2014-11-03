<?php

namespace Tymon\JWTAuth\User;

interface UserInterface
{
    /**
     * Get the user by the given key, value
     *
     * @param  mixed  $key
     * @param  mixed  $value
     */
    public function getBy($key, $value);
}