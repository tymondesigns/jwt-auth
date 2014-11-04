<?php

namespace Tymon\JWTAuth\Providers\Storage;

use Tymon\JWTAuth\Storage\StorageInterface;

class Registry
{
    /**
     * @var \Tymon\JWTAuth\Storage\StorageInterface
     */
    protected $storage;

    /**
     * @param \Tymon\JWTAuth\Storage\StorageInterface $storage
     */
    public function __construct(StorageInterface $storage)
    {
        $this->storage = $storage;
    }

    public function add($token)
    {
        $this->storage->add($token);
    }
}
