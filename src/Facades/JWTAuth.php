<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Facades;

use Tymon\JWTAuth\Token;
use Tymon\JWTAuth\Manager;
use Tymon\JWTAuth\Payload;
use Tymon\JWTAuth\Blacklist;
use Tymon\JWTAuth\Claims\Factory;
use Illuminate\Support\Facades\Facade;
use Tymon\JWTAuth\Contracts\Providers\JWT as Provider;

/**
 * List all of the public methods of JWTAuth\Manager, since this class exposes them
 * via composition.
 *
 * @method static Token   encode(Payload $payload)
 * @method static Payload decode(Token $token, bool $checkBlacklist = true)
 * @method Factory   getPayloadFactory()
 * @method Provider  getJWTProvider()
 * @method Blacklist getBlacklist()
 * @method bool      setBlacklistEnabled($enabled)
 * @method Manager   setPersistentClaims(array $claims)
 * @method Manager   customClaims(array $customClaims)
 * @method Manager   claims(array $customClaims)
 * @method array     getCustomClaims()
 * @method Manager   setRefreshFlow($refreshFlow = true)
 */
class JWTAuth extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'tymon.jwt.auth';
    }
}
