<?php

namespace Tymon\JWTAuth\Providers\Storage;

interface StorageInterface
{
    public function add($key, $value, $minutes);

    public function has($key);

    public function destroy($key);

    public function flush();
}
