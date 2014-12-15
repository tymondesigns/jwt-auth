<?php

namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Providers\Storage\StorageInterface;
use Tymon\JWTAuth\Payload;

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
     * @param \Tymon\JWTAuth\Payload  $payload
     */
    public function add(Payload $payload)
    {
        list($exp, $jti) = $payload->get(['exp', 'jti']);

        // there is no need to add the token to the blacklist
        // if the token has already expired
        if ($exp > time()) {
            // add 60 seconds to abate any potential overlap
            return $this->storage->add($jti, [], ($exp - time()) + 60);
        }

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
     * @param \Tymon\JWTAuth\Payload  $payload
     */
    public function remove(Payload $payload)
    {
        return $this->storage->destroy($payload['jti']);
    }

    /**
     * Remove all tokens from the blacklist
     */
    public function clear()
    {
        return $this->storage->flush();
    }
}
