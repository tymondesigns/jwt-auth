<?php

namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Providers\JWT\JWTInterface;

trait Driver
{

	/**
     * @var \Tymon\JWTAuth\JWT\AbstractJWT
     */
    protected $provider;

    /**
     * Define that there must be a get method on the class that uses this trait
     *
     * @return mixed
     */
    abstract function get();

    /**
     * Encode the payload array
     *
     * @return string
     */
    public function encode()
    {
    	return $this->provider->encode($this->get());
    }

    /**
     * Decode the token
     *
     * @return array
     */
    public function decode()
    {
    	return $this->provider->decode($this->get());
    }

    /**
     * Set the JWT provider
     *
     * @param \Tymon\JWTAuth\Providers\JWT\JWTInterface  $provider
     */
    public function setProvider(JWTInterface $provider)
    {
        $this->provider = $provider;

        return $this;
    }

}