<?php declare(strict_types=1);

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Providers\Auth;

use Illuminate\Contracts\Auth\Guard as GuardContract;
use Tymon\JWTAuth\Contracts\Providers\Auth;

class Illuminate implements Auth
{
    /**
     * The authentication guard.
     *
     * @var \Illuminate\Contracts\Auth\Guard
     */
    protected $auth;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Guard  $auth
     *
     */
    public function __construct(GuardContract $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Check a user's credentials.
     *
     * @param  array  $credentials
     *
     */
    public function byCredentials(array $credentials): bool
    {
        return $this->auth->once($credentials);
    }

    /**
     * Authenticate a user via the id.
     *
     * @param  mixed  $id
     *
     */
    public function byId($id): bool
    {
        return $this->auth->onceUsingId($id);
    }

    /**
     * Get the currently authenticated user.
     *
     * @return mixed
     */
    public function user()
    {
        return $this->auth->user();
    }
}
