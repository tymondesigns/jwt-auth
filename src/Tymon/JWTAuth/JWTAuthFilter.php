<?php namespace Tymon\JWTAuth;

use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Exception;

class JWTAuthFilter {
	
	public function filter($route, $request)
	{
		try
		{
			$token = $this->getToken($request);
		}
		catch(Exception $e)
		{
			return false;
		}

		return true;
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
		catch (Exception $exception)
		{
			if ( ! $token = $request->query('token', false) )
			{
				throw $exception;
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