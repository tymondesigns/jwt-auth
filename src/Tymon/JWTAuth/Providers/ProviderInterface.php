<?php namespace Tymon\JWTAuth\Providers;

interface ProviderInterface {

	public function encode($subject, array $customClaims = []);

	public function decode($token = null);

}