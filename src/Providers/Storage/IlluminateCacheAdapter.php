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

use Illuminate\Cache\CacheManager;

class IlluminateCacheAdapter implements StorageInterface
{
    /**
     * @var \Illuminate\Cache\CacheManager
     */
    protected $cache;

    /**
     * @var string
     */
    protected $tag = 'tymon.jwt';

    /**
     * @param \Illuminate\Cache\CacheManager  $cache
     */
    public function __construct(CacheManager $cache)
    {
        $this->cache = $cache;
    }

    /**
     * Add a new item into storage.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  int  $minutes
     * @return void
     */
    public function add($key, $value, $minutes)
    {
        $this->cache()->put($key, $value, $this->calculateTTL($minutes));
    }

    /**
     * Check whether a key exists in storage.
     *
     * @param  string  $key
     * @return bool
     */
    public function has($key)
    {
        return $this->cache()->has($key);
    }

    /**
     * Remove an item from storage.
     *
     * @param  string  $key
     * @return bool
     */
    public function destroy($key)
    {
        return $this->cache()->forget($key);
    }

    /**
     * Remove all items associated with the tag.
     *
     * @return void
     */
    public function flush()
    {
        $this->cache()->flush();
    }

    /**
     * Return the cache instance with tags attached.
     *
     * @return \Illuminate\Cache\CacheManager|\Illuminate\Cache\TaggedCache
     */
    protected function cache()
    {
        if (! method_exists($this->cache, 'tags')) {
            return $this->cache;
        }

        return $this->cache->tags($this->tag);
    }

    /**
     * Calculates the cache TTL, accounting for API differences introduced in Laravel 5.8.
     *
     * @param  int $ttl
     * @return int Cache TTL in minutes or seconds depending on the version of `illuminate/cache` installed
     */
    protected function calculateTTL($ttl)
    {
        // There may be a more reliable check to use, but for now rely on the presence of classes introduced in 5.8 to decide which behavior to use
        if (class_exists('Illuminate\Cache\DynamoDbLock')) {
            $ttl = $ttl * 60;
        }

        return $ttl;
    }
}
