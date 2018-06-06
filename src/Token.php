<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Contracts\Providers\JWT;
use Tymon\JWTAuth\Validators\TokenValidator;

class Token
{
    /**
     * @var \Tymon\JWTAuth\Contracts\Providers\JWT
     */
    protected static $jwtProvider;

    /**
     * @var \Tymon\JWTAuth\Factory
     */
    protected static $payloadFactory;

    /**
     * @var \Tymon\JWTAuth\Payload
     */
    private $payload;

    /**
     * @var string
     */
    private $value;

    /**
     * Create a new JSON Web Token.
     *
     * @param  \Tymon\JWTAuth\Payload|string  $value
     *
     * @return void
     */
    public function __construct($value)
    {
        if (is_string($value)) {
            $this->value = (string) (new TokenValidator)->check($value);
        } else {
            $this->payload = $value;
        }
    }

    /**
     * Get the token.
     *
     * @return string
     */
    public function get()
    {
        if (null === $this->value) {
            $this->value = self::$jwtProvider->encode($this->payload->toArray());
        }

        return $this->value;
    }

    /**
     * Get the payload.
     *
     * @param bool $refreshFlow
     * @return array|Payload
     */
    public function getPayload($refreshFlow)
    {
        if (null === $this->payload) {
            $payloadArray = self::$jwtProvider->decode($this->value);

            $this->payload = self::$payloadFactory->setRefreshFlow($refreshFlow)
                ->customClaims($payloadArray)
                ->make();
        }

        return $this->payload;
    }

    /**
     * Get the token when casting to string.
     *
     * @return string
     */
    public function __toString()
    {
        return $this->get();
    }

    /**
     * Set jwt provider.
     *
     * @param \Tymon\JWTAuth\Contracts\Providers\JWT $provider
     */
    public static function setJwtProvider(JWT $provider)
    {
        self::$jwtProvider = $provider;
    }

    /**
     * Set payload factory.
     *
     * @param \Tymon\JWTAuth\Factory $factory
     */
    public static function setPayloadFactory(Factory $factory)
    {
        self::$payloadFactory = $factory;
    }
}
