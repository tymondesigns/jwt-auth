<?php

namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Providers\Storage\StorageInterface;

class Blacklist
{
    /**
     * @var \Tymon\JWTAuth\JWT\JWTInterface
     */
    protected $jwt;

    /**
     * @var \Tymon\JWTAuth\Providers\Storage\StorageInterface
     */
    protected $storage;

    /**
     * @param \Tymon\JWTAuth\Providers\JWT\JWTInterface  $jwt
     * @param \Tymon\JWTAuth\Providers\Storage\StorageInterface  $storage
     */
    public function __construct(JWTInterface $jwt, StorageInterface $storage)
    {
        $this->jwt = $jwt;
        $this->storage = $storage;
    }

    /**
     * Add the token (jti claim) to the blacklist
     *
     * @param string  $jti
     */
    public function add($token)
    {
        list($exp, $jti) = $this->jwt->decode($token)->get(['exp', 'jti']);

        // there is no need to add the token to the blacklist
        // if the token has already expired
        if ($exp > time()) {
            // add 60 seconds to abate any potential overlap
            return $this->storage->add($jti, [], ($exp - time()) + 60);
        }

        return true;
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
