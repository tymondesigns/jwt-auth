<?php

declare(strict_types=1);

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Claims;

use Illuminate\Support\Arr;

class Factory
{
    /**
     * The classes map.
     *
     * @var array
     */
    private static $classMap = [
        'aud' => Audience::class,
        'exp' => Expiration::class,
        'iat' => IssuedAt::class,
        'iss' => Issuer::class,
        'jti' => JwtId::class,
        'nbf' => NotBefore::class,
        'sub' => Subject::class,
    ];

    /**
     * Get the instance of the claim when passing the name and value.
     */
    public static function get(string $name, $value = null, array $options = []): Claim
    {
        $claim = static::has($name)
            ? call_user_func([static::$classMap[$name], 'make'], $value)
            : new Custom($name, $value);

        $claim = method_exists($claim, 'setLeeway')
            ? $claim->setLeeway(Arr::get($options, 'leeway', 0))
            : $claim;

        return method_exists($claim, 'setMaxRefreshPeriod')
            ? $claim->setMaxRefreshPeriod(Arr::get($options, 'max_refresh_period'))
            : $claim;
    }

    /**
     * Check whether the claim exists.
     */
    public static function has(string $name): bool
    {
        return array_key_exists($name, static::$classMap);
    }
}
