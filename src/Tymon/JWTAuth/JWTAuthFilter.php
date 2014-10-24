<?php namespace Tymon\JWTAuth;

use Tymon\JWTAuth\JWTAuth;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Events\Dispatcher;
use Response;

class JWTAuthFilter {
	
	/**
	 * @var \Illuminate\Events\Dispatcher
	 */
	protected $events;

	/**
	 * @var \Tymon\JWTAuth\JWTAuth
	 */
	protected $auth;

	public function __construct(Dispatcher $events, JWTAuth $auth)
	{
		$this->events = $events;
		$this->auth = $auth;
	}

	/**
	 * Filter the request
	 * 
	 * @param  \Illuminate\Routing\Router $route   
	 * @param  \Illuminate\Http\Request   $request 
	 * @return \Illuminate\Http\Response          
	 */
	public function filter($route, $request)
	{
		if ( ! $token = $this->auth->getToken($request) )
		{
			$response = $this->events->fire('tymon.jwt.absent', [], true);
			return $response ?: Response::json(['error' => 'token_not_provided'], 400);
		}

		try
		{
			$user = $this->auth->toUser($token);
		}
		catch(TokenExpiredException $e)
		{
			$response = $this->events->fire('tymon.jwt.expired', $e->getMessage(), true);
			return $response ?: Response::json(['error' => 'token_expired'], 401);
		}
		catch(JWTException $e)
		{
			$response = $this->events->fire('tymon.jwt.invalid', $e->getMessage(), true);
			return $response ?: Response::json(['error' => 'token_invalid'], 401);
		}

		if (! $user)
		{
			$response = $this->events->fire('tymon.jwt.user_not_found', [], true);
			return $response ?: Response::json(['error' => 'user_not_found'], 404);
		}

		$this->events->fire('tymon.jwt.valid', $user);
	}

}