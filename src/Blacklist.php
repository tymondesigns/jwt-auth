<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Providers\Storage\StorageInterface;

class Blacklist
{
    /**
     * @var \Tymon\JWTAuth\Providers\Storage\StorageInterface
     */
    protected $storage;

    /**
     * Number of minutes from issue date in which a JWT can be refreshed.
     *
     * @var int
     */
    protected $refreshTTL = 20160;

    /**
     * @param \Tymon\JWTAuth\Providers\Storage\StorageInterface  $storage
     */
    public function __construct(StorageInterface $storage)
    {
        $this->storage = $storage;
    }

    /**
     * Add the token (jti claim) to the blacklist.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     * @return bool
     */
    public function add(Payload $payload)
    {
        $exp = Utils::timestamp($payload['exp']);
        $refreshExp = Utils::timestamp($payload['iat'])->addMinutes($this->refreshTTL);

        // there is no need to add the token to the blacklist
        // if the token has already expired AND the refresh_ttl
        // has gone by
        if ($exp->isPast() && $refreshExp->isPast()) {
            return false;
        }

        // Set the cache entry's lifetime to be equal to the amount
        // of refreshable time it has remaining (which is the larger
        // of `exp` and `iat+refresh_ttl`), rounded up a minute
        $cacheLifetime = $exp->max($refreshExp)->addMinute()->diffInMinutes();

        $this->storage->add($payload['jti'], [], $cacheLifetime);

        return true;
    }

    /**
     * Determine whether the token has been blacklisted.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     * @return bool
     */
    public function has(Payload $payload)
    {
        return $this->storage->has($payload['jti']);
    }

    /**
     * Remove the token (jti claim) from the blacklist.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     * @return bool
     */
    public function remove(Payload $payload)
    {
        return $this->storage->destroy($payload['jti']);
    }

    /**
     * Remove all tokens from the blacklist.
     *
     * @return bool
     */
    public function clear()
    {
        $this->storage->flush();

        return true;
    }

    /**
     * Set the refresh time limit.
     *
     * @param  int
     *
     * @return $this
     */
    public function setRefreshTTL($ttl)
    {
        $this->refreshTTL = (int) $ttl;

        return $this;
    }
}
