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

use Cartalyst\Sentinel\Sentinel as SentinelAuth;
use Tymon\JWTAuth\Contracts\Providers\Auth;

class Sentinel implements Auth
{
    /**
     * The sentinel authentication.
     *
     * @var \Cartalyst\Sentinel\Sentinel
     */
    protected $sentinel;

    /**
     * Constructor.
     *
     * @param  \Cartalyst\Sentinel\Sentinel  $sentinel
     *
     */
    public function __construct(SentinelAuth $sentinel)
    {
        $this->sentinel = $sentinel;
    }

    /**
     * Check a user's credentials.
     *
     * @param  array  $credentials
     *
     * @return mixed
     */
    public function byCredentials(array $credentials)
    {
        return $this->sentinel->stateless($credentials);
    }

    /**
     * Authenticate a user via the id.
     *
     * @param  mixed  $id
     *
     */
    public function byId($id): bool
    {
        if ($user = $this->sentinel->getUserRepository()->findById($id)) {
            $this->sentinel->setUser($user);

            return true;
        }

        return false;
    }

    /**
     * Get the currently authenticated user.
     *
     */
    public function user(): \Cartalyst\Sentinel\Users\UserInterface
    {
        return $this->sentinel->getUser();
    }
}
