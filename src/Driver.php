<?php

namespace Tymon\JWTAuth;

use Tymon\JWTAuth\JWT\JWTInterface;

trait Driver
{

	/**
     * @var \Tymon\JWTAuth\JWT\JWTInterface
     */
    protected $jwt;

    /**
     * @param \Tymon\JWTAuth\JWT\JWTInterface  $jwt
     */
    public function __construct(JWTInterface $jwt)
    {
        $this->jwt = $jwt;
    }

    /**
     * There must be a get method on the class that uses this trait
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
    	return $this->jwt->encode($this->get());
    }

    /**
     * Decode the token
     *
     * @return array
     */
    public function decode()
    {
    	return $this->jwt->decode($this->get());
    }

}