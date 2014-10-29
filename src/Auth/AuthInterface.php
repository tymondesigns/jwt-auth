<?php

namespace Tymon\JWTAuth\Auth;

interface AuthInterface
{
    /**
     * Check a user's credentials
     *
     * @param  array  $credentials
     * @return bool
     */
    public function check(array $credentials = []);

    /**
     * Authenticate a user via the id
     *
     * @param  mixed  $id
     * @return bool
     */
    public function checkUsingId($id);

    /**
     * Get the currently authenticated user
     *
     * @return mixed
     */
    public function user();
}
