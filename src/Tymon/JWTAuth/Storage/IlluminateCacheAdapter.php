<?php namespace Tymon\JWTAuth\Storage;

use Illuminate\Cache\Repository;

class IlluminateCacheAdapter
{

	/**
     * @param \Illuminate\Cache\Repository  $cache
     */
    public function __construct(Repository $cache)
    {
        $this->cache = $cache;
    }

	public function add($token)
	{
		$this->cache->put($token)
	}

	public function exists($token)
	{

	}

	public function destroy($token)
	{

	}
}