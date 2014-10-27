<?php namespace Tymon\JWTAuth\Storage;

use Tymon\JWTAuth\Storage\Storable;

class Registry
{
    /**
     * @var \Tymon\JWTAuth\Storage\Storable
     */
    protected $storage;
    
    /**
     * @param \Tymon\JWTAuth\Storage\Storable  $storage
     */
    public function __construct(Storable $storage)
    {
        $this->storage = $storage;
    }

    public function add($token)
    {
        $this->storage->add($token);
    }

}
