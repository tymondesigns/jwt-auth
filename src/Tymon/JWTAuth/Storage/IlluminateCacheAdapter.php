<?php

namespace Tymon\JWTAuth\Storage;

use Illuminate\Cache\Repository;

class IlluminateCacheAdapter implements Storable
{
    /**
     * @var \Illuminate\Cache\Repository
     */
    protected $cache;

    /**
     * @var string
     */
    protected $tag = 'tymon.jwt';

    /**
     * @param \Illuminate\Cache\Repository $cache
     */
    public function __construct(Repository $cache)
    {
        $this->cache = $cache;
    }

    public function add($key, $value, $minutes)
    {
        return $this->cache->tags($this->tag)->put($key, $value, $minutes);
    }

    public function has($key)
    {
        return $this->cache->tags($this->tag)->has($key);
    }

    public function destroy($key)
    {
        return $this->cache->tags($this->tag)->forget($key);
    }

    public function flush()
    {
        return $this->cache->tags($this->tag)->flush();
    }
}
