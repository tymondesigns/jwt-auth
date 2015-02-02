<?php

namespace Tymon\JWTAuth\Providers\Storage;

interface StorageInterface
{
    /**
     * @param string $key
     * @param integer $minutes
     * @return void
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
}
