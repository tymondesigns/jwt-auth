<?php namespace Tymon\JWTAuth;

use Tymon\JWTAuth\JWTAuth;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Illuminate\Events\Dispatcher;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Exception;

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
	 * @return void          
	 */
	public function filter($route, $request)
	{
		try
		{
			$token = $this->getToken($request);
			$user = $this->auth->toUser($token);
		}
		catch(TokenExpiredException $e)
		{
			$this->events->fire('tymon.jwt.expired', $e->getMessage());
		}
		catch(Exception $e)
		{
			$this->events->fire('tymon.jwt.invalid', $e->getMessage());
		}

		$this->events->fire('tymon.jwt.valid', $user);
	}

	/**
	 * Get the token from the request
	 *
	 * @param  \Illuminate\Http\Request $request
	 * @return string
	 */
	protected function getToken($request)
	{
		try
		{
			$token = $this->parseAuthHeader($request);
		}
		catch (BadRequestHttpException $e)
		{
			if ( ! $token = $request->query('token', false) )
			{
				throw $e;
			}
		}

		return $token;
	}

	/**
	 * Parse token from the authorization header
	 *
	 * @param  \Illuminate\Http\Request $request
	 * @return string
	 * @throws \Symfony\Component\HttpKernel\Exception\BadRequestHttpException
	 */
	protected function parseAuthHeader($request)
	{
		$header = $request->headers->get('authorization');

		if ( ! starts_with( strtolower($header), 'bearer' ) ) {
			throw new BadRequestHttpException;
		}

		return trim( str_ireplace( 'bearer', '', $header ) );
	}

}