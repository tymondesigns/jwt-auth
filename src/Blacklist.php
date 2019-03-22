<?php

declare(strict_types=1);

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Claims\JwtId;
use Tymon\JWTAuth\Claims\Expiration;
use function Tymon\JWTAuth\Support\now;
use function Tymon\JWTAuth\Support\is_future;
use function Tymon\JWTAuth\Support\timestamp;
use Tymon\JWTAuth\Contracts\Providers\Storage;

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
     * The unique key held within the blacklist.
     *
     * @var string
     */
    protected $key = JwtId::NAME;

    /**
     * The value to store when blacklisting forever.
     *
     * @var string
     */
    const FOREVER = 'FOREVER';

    /**
     * The key to use for the blacklist value.
     *
     * @var string
     */
    const VALID_UNTIL = 'valid_until';

    /**
     * Constructor.
     */
    public function __construct(Storage $storage)
    {
        $this->storage = $storage;
    }

    /**
     * Add the token (jti claim) to the blacklist.
     */
    public function add(Payload $payload): void
    {
        // if there is no exp claim then add the jwt to
        // the blacklist indefinitely
        if (! $payload->hasKey(Expiration::NAME)) {
            $this->addForever($payload);

            return;
        }

        // if we have already added this token to the blacklist
        if (! empty($this->storage->get($this->getKey($payload)))) {
            return;
        }

        $this->storage->add(
            $this->getKey($payload),
            [static::VALID_UNTIL => $this->getGraceTimestamp()],
            $this->getMinutesUntilExpired($payload)
        );
    }

    /**
     * Get the number of minutes until the token expiry.
     */
    protected function getMinutesUntilExpired(Payload $payload): int
    {
        $exp = timestamp($payload[Expiration::NAME]);

        // find the number of minutes until the expiration date,
        // plus 1 minute to avoid overlap
        return now()
            ->subMinute()
            ->diffInRealMinutes($exp);
    }

    /**
     * Add the token (jti claim) to the blacklist indefinitely.
     */
    public function addForever(Payload $payload): void
    {
        $this->storage->forever($this->getKey($payload), static::FOREVER);
    }

    /**
     * Determine whether the token has been blacklisted.
     */
    public function has(Payload $payload): bool
    {
        $val = $this->storage->get($this->getKey($payload));

        // exit early if the token was blacklisted forever,
        if ($val === static::FOREVER) {
            return true;
        }

        // check whether the expiry + grace has past
        return ! empty($val) && ! is_future($val[static::VALID_UNTIL]);
    }

    /**
     * Remove the token from the blacklist.
     */
    public function remove(Payload $payload): void
    {
        $this->storage->destroy($this->getKey($payload));
    }

    /**
     * Remove all tokens from the blacklist.
     */
    public function clear(): void
    {
        $this->storage->flush();
    }

    /**
     * Get the timestamp when the blacklist comes into effect
     * This defaults to immediate (0 seconds).
     */
    protected function getGraceTimestamp(): int
    {
        return now()
            ->addSeconds($this->gracePeriod)
            ->getTimestamp();
    }

    /**
     * Set the grace period.
     */
    public function setGracePeriod(int $gracePeriod): self
    {
        $this->gracePeriod = $gracePeriod;

        return $this;
    }

    /**
     * Get the grace period.
     */
    public function getGracePeriod(): int
    {
        return $this->gracePeriod;
    }

    /**
     * Get the unique key held within the blacklist.
     */
    public function getKey(Payload $payload): string
    {
        return (string) $payload($this->key);
    }

    /**
     * Set the unique key held within the blacklist.
     */
    public function setKey(string $key): self
    {
        $this->key = $key;

        return $this;
    }
}
