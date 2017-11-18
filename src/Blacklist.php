<?php declare(strict_types=1);

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Contracts\Providers\Storage;
use Tymon\JWTAuth\Support\Utils;

class Blacklist
{
    /**
     * The storage.
     *
     * @var \Tymon\JWTAuth\Contracts\Providers\Storage
     */
    protected $storage;

    /**
     * The grace period when a token is blacklisted. In seconds.
     *
     * @var int
     */
    protected $gracePeriod = 0;

    /**
     * Number of minutes from issue date in which a JWT can be refreshed.
     *
     * @var int
     */
    protected $refreshTTL = 20160;

    /**
     * The unique key held within the blacklist.
     *
     * @var string
     */
    protected $key = 'jti';

    /**
     * Constructor.
     *
     * @param  \Tymon\JWTAuth\Contracts\Providers\Storage  $storage
     *
     */
    public function __construct(Storage $storage)
    {
        $this->storage = $storage;
    }

    /**
     * Add the token (jti claim) to the blacklist.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     *
     */
    public function add(Payload $payload): bool
    {
        // if there is no exp claim then add the jwt to
        // the blacklist indefinitely
        if (! $payload->hasKey('exp')) {
            return $this->addForever($payload);
        }

        $this->storage->add(
            $this->getKey($payload),
            ['valid_until' => $this->getGraceTimestamp()],
            $this->getMinutesUntilExpired($payload)
        );

        return true;
    }

    /**
     * Get the number of minutes until the token expiry.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     *
     */
    protected function getMinutesUntilExpired(Payload $payload): int
    {
        $exp = Utils::timestamp($payload['exp']);
        $iat = Utils::timestamp($payload['iat']);

        // get the latter of the two expiration dates and find
        // the number of minutes until the expiration date,
        // plus 1 minute to avoid overlap
        return $exp->max($iat->addMinutes($this->refreshTTL))->addMinute()->diffInMinutes();
    }

    /**
     * Add the token (jti claim) to the blacklist indefinitely.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     *
     */
    public function addForever(Payload $payload): bool
    {
        $this->storage->forever($this->getKey($payload), 'forever');

        return true;
    }

    /**
     * Determine whether the token has been blacklisted.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     *
     */
    public function has(Payload $payload): bool
    {
        $val = $this->storage->get($this->getKey($payload));

        // exit early if the token was blacklisted forever,
        if ($val === 'forever') {
            return true;
        }

        // check whether the expiry + grace has past
        return ! empty($val) && ! Utils::isFuture($val['valid_until']);
    }

    /**
     * Remove the token (jti claim) from the blacklist.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     *
     */
    public function remove(Payload $payload): bool
    {
        return $this->storage->destroy($this->getKey($payload));
    }

    /**
     * Remove all tokens from the blacklist.
     *
     */
    public function clear(): bool
    {
        $this->storage->flush();

        return true;
    }

    /**
     * Get the timestamp when the blacklist comes into effect
     * This defaults to immediate (0 seconds).
     *
     */
    protected function getGraceTimestamp(): int
    {
        return Utils::now()->addSeconds($this->gracePeriod)->getTimestamp();
    }

    /**
     * Set the grace period.
     *
     * @param  int  $gracePeriod
     *
     * @return $this
     */
    public function setGracePeriod(int $gracePeriod)
    {
        $this->gracePeriod = (int) $gracePeriod;

        return $this;
    }

    /**
     * Get the grace period.
     *
     */
    public function getGracePeriod(): int
    {
        return $this->gracePeriod;
    }

    /**
     * Get the unique key held within the blacklist.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     *
     * @return mixed
     */
    public function getKey(Payload $payload)
    {
        return $payload($this->key);
    }

    /**
     * Set the unique key held within the blacklist.
     *
     * @param  string  $key
     *
     * @return $this
     */
    public function setKey(string $key)
    {
        $this->key = value($key);

        return $this;
    }

    /**
     * Set the refresh time limit.
     *
     * @param  int  $ttl
     *
     * @return $this
     */
    public function setRefreshTTL(int $ttl)
    {
        $this->refreshTTL = (int) $ttl;

        return $this;
    }

    /**
     * Get the refresh time limit.
     *
     */
    public function getRefreshTTL(): int
    {
        return $this->refreshTTL;
    }
}
