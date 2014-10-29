<?php

namespace Tymon\JWTAuth\Storage;

interface StorageInterface
{
    public function add($key, $value, $minutes);

    public function has($key);

    public function destroy($key);

    public function flush();
}
