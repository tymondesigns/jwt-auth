<?php

namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Providers\Storage\StorageInterface;

class Blacklist
{
    /**
     * @var \Tymon\JWTAuth\Providers\Storage\StorageInterface
     */
    protected $storage;

    /**
     * @param \Tymon\JWTAuth\Providers\Storage\StorageInterface $storage
     */
    public function __construct(StorageInterface $storage)
    {
        $this->storage = $storage;
    }

    /**
     * Add the token (jti claim) to the blacklist
     *
     * @param string  $jti
     */
    public function add($jti, $expiry)
    {
        return $this->storage->add($jti, [], $expiry);
    }

    /**
     * Determine whether the jti has been blacklisted
     *
     * @param  string  $jti
     * @return boolean
     */
    public function has($jti)
    {
        return $this->storage->has($jti);
    }

    /**
     * Remove the token (jti claim) from the blacklist
     *
     * @param string  $jti
     */
    public function remove($jti)
    {
        return $this->storage->destroy($jti);
    }

    /**
     * Remove all tokens from the blacklist
     */
    public function clear()
    {
        return $this->storage->flush();
    }
}
