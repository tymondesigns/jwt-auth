<?php

namespace Tymon\JWTAuth\Contracts\Providers;

interface Auth
{
    /**
     * Check a user's credentials
     *
     * @param  array  $credentials
     *
     * @return boolean
     */
    public function byCredentials(array $credentials = []);

    /**
     * Authenticate a user via the id
     *
     * @param  mixed  $id
     *
     * @return boolean
     */
    public function byId($id);

    /**
     * Get the currently authenticated user
     *
     * @return mixed
     */
    public function user();
}
