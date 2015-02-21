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
     * @param \Tymon\JWTAuth\Providers\Storage\StorageInterface  $storage
     */
    public function __construct(StorageInterface $storage)
    {
        $this->storage = $storage;
    }

    /**
     * Add the token (jti claim) to the blacklist
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     * @return boolean
     */
    public function add(Payload $payload)
    {
        $exp = Utils::timestamp($payload['exp']);

        // there is no need to add the token to the blacklist
        // if the token has already expired
        if ($exp->isPast()) {
            return false;
        }

        // add a minute to abate potential overlap
        $minutes = $exp->diffInMinutes(Utils::now()->subMinute());

        $this->storage->add($payload['jti'], [], $minutes);

        return true;
    }

    /**
     * Determine whether the token has been blacklisted
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     * @return boolean
     */
    public function has(Payload $payload)
    {
        return $this->storage->has($payload['jti']);
    }

    /**
     * Remove the token (jti claim) from the blacklist
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     * @return boolean
     */
    public function remove(Payload $payload)
    {
        return $this->storage->destroy($payload['jti']);
    }

    /**
     * Remove all tokens from the blacklist
     *
     * @return boolean
     */
    public function clear()
    {
        $this->storage->flush();

        return true;
    }
}
