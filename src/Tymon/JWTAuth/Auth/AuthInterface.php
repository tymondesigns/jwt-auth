<?php namespace Tymon\JWTAuth\Auth;

interface AuthInterface
{
	/**
	 * Log a user into the application without sessions or cookies.
	 *
	 * @param  array  $credentials
	 * @return bool
	 */
	public function check(array $credentials = []);

	/**
	 * Log the given user ID into the application without sessions or cookies.
	 * 
	 * @param  mixed  $id
	 * @return bool
	 */
	public function checkUsingId($id);

	/**
	 * Get the currently authenticated user.
	 *
	 * @return mixed
	 */
	public function user();
}