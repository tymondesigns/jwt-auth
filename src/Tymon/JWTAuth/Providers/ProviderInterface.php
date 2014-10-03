<?php namespace Tymon\JWTAuth\Providers;

interface ProviderInterface {

	/**
	 * @return \Tymon\JWTAuth\Token
	 */
	public function encode($subject, array $customClaims = []);

	/**
	 * @param string $token
	 * @return \Tymon\JWTAuth\Payload
	 */
	public function decode($token = null);

}