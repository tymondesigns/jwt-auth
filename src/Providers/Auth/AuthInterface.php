<?php

namespace Tymon\JWTAuth\Providers\Auth;

interface AuthInterface
{
    /**
     * Check a user's credentials
     *
     * @param  array  $credentials
     * @return bool
     */
    public function byCredentials(array $credentials = []);

    /**
     * Authenticate a user via the id
     *
     * @param  mixed  $id
     * @return bool
     */
    public function byId($id);

    /**
     * Get the currently authenticated user
     *
     * @return mixed
     */
    public function user();
}
