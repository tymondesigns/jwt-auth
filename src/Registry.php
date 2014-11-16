<?php

namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Providers\Storage\StorageInterface;

class Registry
{
	/**
	 * @var \Tymon\JWTAuth\Providers\Storage\StorageInterface
	 */
	protected $storage;

	/**
	 * @param \Tymon\JWTAuth\Providers\Storage\StorageInterface $storage
	 */
	public function __construct(StorageInterface $storage)
	{
		$this->storage = $storage;
	}

	/**
	 * Add the token (jti claim) to storage
	 *
	 * @param mixed  $userId
	 * @param mixed  $jti
	 */
	public function addToken($userId, $jti)
	{
		$tokens = [$jti];

		if ($this->storage->has($userId)) {
			$tokens = $this->storage->get($userId);
			$tokens[] = $jti;
		}

		return $this->storage->add($userId, $tokens);
	}
}
