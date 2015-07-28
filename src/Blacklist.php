<?php

/*
 * This file is part of jwt-auth
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth;

use Carbon\Carbon;
use Tymon\JWTAuth\Support\Utils;
use Tymon\JWTAuth\Contracts\Providers\Storage;

class Blacklist
{
    /**
     * @var \Tymon\JWTAuth\Contracts\Providers\Storage
     */
    protected $storage;

    /**
     * The grace period when a token is blacklisted. In seconds
     *
     * @var integer
     */
    protected $gracePeriod = 0;

    /**
     * @param \Tymon\JWTAuth\Contracts\Providers\Storage  $storage
     */
    public function __construct(Storage $storage)
    {
        $this->storage = $storage;
    }

    /**
     * Add the token (jti claim) to the blacklist
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     *
     * @return boolean
     */
    public function add(Payload $payload)
    {
        $exp = Utils::timestamp($payload['exp']);

        // there is no need to add the token to the blacklist
        // if it has already expired
        if ($exp->isPast()) {
            return false;
        }

        // add a minute to abate potential overlap
        $minutes = $exp->diffInMinutes(Utils::now()->subMinute());

        $this->storage->add($payload['jti'], ['valid_until' => $this->getGraceTimestamp($exp)], $minutes);

        return true;
    }

    /**
     * Determine whether the token has been blacklisted
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     *
     * @return boolean
     */
    public function has(Payload $payload)
    {
        $grace = $this->storage->get($payload['jti']);

        // check whether the expiry + grace has past
        if (is_null($grace) || Utils::timestamp($grace['valid_until'])->isFuture()) {
            return false;
        }

        return true;
    }

    /**
     * Remove the token (jti claim) from the blacklist
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     *
     * @return boolean
     */
    public function remove(Payload $payload)
    {
        return $this->storage->destroy($payload['jti']);
    }

    /**
     * Remove all tokens from the blacklist
     *
     * @return boolean
     */
    public function clear()
    {
        $this->storage->flush();

        return true;
    }

    /**
     * Get the timestamp when the blacklist comes into effect
     * This defaults to immediate (0 seconds)
     *
     * @param \Carbon\Carbon $exp
     *
     * @return integer
     */
    protected function getGraceTimestamp(Carbon $exp)
    {
        return (int) $exp->addSeconds($this->gracePeriod)->format('U');
    }

    /**
     * Set the grace period
     *
     * @param  integer
     *
     * @return Blacklist
     */
    public function setGracePeriod($gracePeriod)
    {
        $this->gracePeriod = (int) $gracePeriod;

        return $this;
    }
}
