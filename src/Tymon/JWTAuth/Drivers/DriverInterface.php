<?php namespace Tymon\JWTAuth\Drivers;

interface DriverInterface {

	public function encode($subject, array $customClaims = []);

	public function decode($token = null);

}