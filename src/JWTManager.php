<?php

namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Providers\JWT\JWTInterface;
use Tymon\JWTAuth\Payload;
use Tymon\JWTAuth\Token;

class JWTManager
{

	/**
	 * @var \Tymon\JWTAuth\Providers\JWT\JWTInterface
	 */
	protected $jwt;

	/**
	 * @var \Tymon\JWTAuth\Payload\PayloadFactory
	 */
	protected $payloadFactory;

	/**
	 *  @param \Tymon\JWTAuth\Providers\JWT\JWTInterface  $jwt
	 *  @param \Tymon\JWTAuth\Payload\PayloadFactory  $payloadFactory
	 */
	public function __construct(JWTInterface $jwt, PayloadFactory $payloadFactory)
	{
		$this->jwt = $jwt;
		$this->payloadFactory = $payloadFactory;
	}

	/**
	 * Encode a Payload and return the Token
	 *
	 * @param  \Tymon\JWTAuth\Payload  $payload
	 * @return \Tymon\JWTAuth\Token
	 */
	public function encode(Payload $payload)
	{
		$token = $this->jwt->encode($payload->get());

		return new Token($token);
	}

	/**
	 * Decode a Token and return the Payload
	 *
	 * @param  \Tymon\JWTAuth\Token  $token
	 * @return \Tymon\JWTAuth\Payload
	 */
	public function decode(Token $token)
	{
		$payload = $this->jwt->decode($token->get());

		return $this->payloadFactory->make($payload);
	}

	/**
	 * Refresh a Token and return a new Token
	 *
	 * @param  \Tymon\JWTAuth\Token  $token
	 * @return \Tymon\JWTAuth\Token
	 */
	public function refresh(Token $token)
	{
		list($iat, $sub) = $this->decode($token)->get(['iat', 'sub']);

		// @todo if iat longer than refresh_ttl ago

		return $this->encode($this->payloadFactory->sub($sub)->make());
	}

	/**
	 * Invalidate a Token by adding it to the blacklist
	 *
	 * @param  Token  $token
	 * @return boolean
	 */
	public function invalidate(Token $token)
	{
		return $this->blacklist->add($this->decode($token));
	}

}