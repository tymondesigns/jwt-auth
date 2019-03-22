<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Providers\Storage;

use BadMethodCallException;
use Tymon\JWTAuth\Contracts\Providers\Storage;
use Illuminate\Contracts\Cache\Repository as CacheContract;

class Illuminate implements Storage
{
    /**
     * The cache repository contract.
     *
     * @var \Illuminate\Contracts\Cache\Repository
     */
    protected $cache;

    /**
     * The used cache tag.
     *
     * @var string
     */
    protected $tag = 'tymon.jwt';

    /**
     * @var bool
     */
    protected $supportsTags;

    /**
     * @var string|null
     */
    protected $laravelVersion;

    /**
     * Constructor.
     */
    public function __construct(CacheContract $cache)
    {
        $this->cache = $cache;
    }

    /**
     * Add a new item into storage.
     */
    public function add(string $key, $value, $minutes): void
    {
        // If the laravel version is 5.8 or higher then convert minutes to seconds.
        if ($this->laravelVersion !== null
            && is_int($minutes)
            && version_compare($this->laravelVersion, '5.8', '>=')
        ) {
            $minutes = $minutes * 60;
        }

        $this->cache()->put($key, $value, $minutes);
    }

    /**
     * Add a new item into storage forever.
     */
    public function forever(string $key, $value): void
    {
        $this->cache()->forever($key, $value);
    }

    /**
     * Get an item from storage.
     */
    public function get(string $key)
    {
        return $this->cache()->get($key);
    }

    /**
     * Remove an item from storage.
     */
    public function destroy(string $key): void
    {
        $this->cache()->forget($key);
    }

    /**
     * Remove all items associated with the tag.
     */
    public function flush(): void
    {
        $this->cache()->flush();
    }

    /**
     * Return the cache instance with tags attached.
     */
    protected function cache(): CacheContract
    {
        if ($this->supportsTags === null) {
            $this->determineTagSupport();
        }

        if ($this->supportsTags) {
            return $this->cache->tags($this->tag);
        }

        return $this->cache;
    }

    /**
     * Set the laravel version.
     */
    public function setLaravelVersion(string $version)
    {
        $this->laravelVersion = $version;

        return $this;
    }

    /**
     * Detect as best we can whether tags are supported with this repository & store,
     * and save our result on the $supportsTags flag.
     */
    protected function determineTagSupport(): void
    {
        try {
            // Attempt the repository tags command, which throws exceptions when unsupported
            $this->cache->tags($this->tag);
            $this->supportsTags = true;
        } catch (BadMethodCallException $ex) {
            $this->supportsTags = false;
        }
    }
}
