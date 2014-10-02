<?php namespace Tymon\JWTAuth;

use Tymon\JWTAuth\JWTAuth;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Events\Dispatcher;
use Illuminate\Http\Response;

class JWTAuthFilter {
	
	/**
	 * @var \Illuminate\Events\Dispatcher
	 */
	protected $events;

	/**
	 * @var \Illuminate\Http\Response
	 */
	protected $response;

	/**
	 * @var \Tymon\JWTAuth\JWTAuth
	 */
	protected $auth;

	public function __construct(Dispatcher $events, Response $response, JWTAuth $auth)
	{
		$this->events = $events;
		$this->response = $response;
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
			$this->events->fire('tymon.jwt.absent');
			return $this->response->json(['error' => 'token_not_provided'], 400);
		}

		try
		{
			$user = $this->auth->toUser($token);
		}
		catch(TokenExpiredException $e)
		{
			$this->events->fire('tymon.jwt.expired', $e->getMessage());
			return $this->response->json(['error' => 'token_expired'], 401);
		}
		catch(JWTException $e)
		{
			$this->events->fire('tymon.jwt.invalid', $e->getMessage());
			return $this->response->json(['error' => 'token_invalid'], 401);
		}

		if (! $user)
		{
			$this->events->fire('tymon.jwt.user_not_found');
			return $this->response->json(['error' => 'user_not_found'], 404);
		}

		$this->events->fire('tymon.jwt.valid', $user);
	}

}