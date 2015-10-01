<?php

/*
 * This file is part of jwt-auth
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Providers\Storage;

use Tymon\JWTAuth\Contracts\Providers\Storage;
use Illuminate\Contracts\Cache\Factory as CacheContract;

class Illuminate implements Storage
{
    /**
     * @var \Illuminate\Contracts\Cache\Store
     */
    protected $cache;

    /**
     * @var string
     */
    protected $tag = 'tymon.jwt';

    /**
     * @param \Illuminate\Contracts\Cache\Factory  $cache
     */
    public function __construct(CacheContract $cache)
    {
        $this->cache = $cache;
    }

    /**
     * Add a new item into storage
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  int  $minutes
     *
     * @return void
     */
    public function add($key, $value, $minutes)
    {
        $this->cache()->put($key, $value, $minutes);
    }

    /**
     * Get an item from storage
     *
     * @param  string  $key
     *
     * @return mixed
     */
    public function get($key)
    {
        return $this->cache()->get($key);
    }

    /**
     * Remove an item from storage
     *
     * @param  string  $key
     *
     * @return boolean
     */
    public function destroy($key)
    {
        return $this->cache()->forget($key);
    }

    /**
     * Remove all items associated with the tag
     *
     * @return void
     */
    public function flush()
    {
        $this->cache()->flush();
    }

    /**
     * Return the cache instance with tags attached
     *
     * @return \Illuminate\Contracts\Cache\Store
     */
    protected function cache()
    {
        if (! method_exists($this->cache, 'tags')) {
            return $this->cache;
        }

        return $this->cache->tags($this->tag);
    }
}
