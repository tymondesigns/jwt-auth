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
use Tymon\JWTAuth\Contracts\Providers\Storage;
use Tymon\JWTAuth\Support\Utils;

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
     * Number of minutes from issue date in which a JWT can be refreshed.
     *
     * @var integer
     */
    protected $refreshTTL = 20160;

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
        $refreshExp = Utils::timestamp($payload['iat'])->addMinute($this->refreshTTL);
        $lastExp = $exp->max($refreshExp); // the later of the two expiration dates

        // find the number of minutes until the expiration date, plus 1 minute to avoid overlap
        $minutes = $lastExp->diffInMinutes(Utils::now()->subMinute());

        $this->storage->add($payload['jti'], ['valid_until' => $this->getGraceTimestamp(Carbon::now())], $minutes);

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

    /**
     * Set the refresh time limit
     *
     * @param  integer
     *
     * @return Blacklist
     */
    public function setRefreshTTL($gracePeriod)
    {
        $this->refreshTTL = $ttl;

        return $this;
    }
}
