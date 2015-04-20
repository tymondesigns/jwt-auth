<?php

namespace Tymon\JWTAuth\Providers\Storage;

interface StorageInterface
{
    /**
     * @param string $key
     * @param $value
     * @param integer $minutes
     */
    public function add($key, $value, $minutes);

    /**
     * @param string $key
     * @return boolean
     */
    public function has($key);

    /**
     * @param string $key
     * @return boolean
     */
    public function destroy($key);

    /**
     * @return void
     */
    public function flush();

    /**
     * Get a value given it's key.
     *
     * @param $key
     * @return mixed
     */
    public function get($key);
}
