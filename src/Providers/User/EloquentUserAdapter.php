<?php

namespace Tymon\JWTAuth\Providers\User;

use Illuminate\Database\Eloquent\Model;

class EloquentUserAdapter implements UserInterface
{
    /**
     * @var \Illuminate\Database\Eloquent\Model
     */
    protected $user;

    /**
     * Create a new User instance
     *
     * @param  \Illuminate\Database\Eloquent\Model  $user
     */
    public function __construct(Model $user)
    {
        $this->user = $user;
    }

    /**
     * Get the user by the given key, value
     *
     * @param  mixed  $key
     * @param  mixed  $value
     * @return Illuminate\Database\Eloquent\Model
     */
    public function getBy($key, $value)
    {
        return $this->user->where($key, $value)->first();
    }
}
