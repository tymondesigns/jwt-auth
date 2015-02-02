<?php

namespace Tymon\JWTAuth\Providers\User;

interface UserInterface
{
    /**
     * Get the user by the given key, value
     *
     * @param string $key
     * @param mixed $value
     * @return Illuminate\Database\Eloquent\Model|null
     */
    public function getBy($key, $value);
}
