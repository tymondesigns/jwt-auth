<?php

namespace Tymon\JWTAuth\Providers\Storage;

interface StorageInterface
{
    /**
     * @return void
     */
    public function add($key, $value, $minutes);

    /**
     * @return boolean
     */
    public function has($key);

    /**
     * @return boolean
     */
    public function destroy($key);

    /**
     * @return void
     */
    public function flush();
}
