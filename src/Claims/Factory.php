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

use Tymon\JWTAuth\Options;
use Tymon\JWTAuth\Contracts\Claim as ClaimContract;

class Factory
{
    /**
     * The class map.
     *
     * @var array
     */
    private static $classMap = [
        Audience::NAME => Audience::class,
        Expiration::NAME => Expiration::class,
        IssuedAt::NAME => IssuedAt::class,
        Issuer::NAME => Issuer::class,
        JwtId::NAME => JwtId::class,
        NotBefore::NAME => NotBefore::class,
        Subject::NAME => Subject::class,
        HashedSubject::NAME => HashedSubject::class,
    ];

    /**
     * Get the instance of the claim when passing the name and value.
     */
    public static function get(string $name, $value = null, ?Options $options = null): ClaimContract
    {
        $options = $options ?? new Options();

        $claim = static::has($name)
            ? call_user_func([static::$classMap[$name], 'make'], $value)
            : new Custom($name, $value);

        return static::applyClaimMethods($claim, [
            'setLeeway' => $options->leeway(),
            'setMaxRefreshPeriod' => $options->maxRefreshPeriod(),
        ]);
    }

    /**
     * Check whether the claim exists.
     */
    public static function has(string $name): bool
    {
        return array_key_exists($name, static::$classMap);
    }

    /**
     * Apply a multiple methods to the given claim if they exist.
     */
    protected static function applyClaimMethods(ClaimContract $claim, array $data): ClaimContract
    {
        foreach ($data as $method => $value) {
            $claim = method_exists($claim, $method)
                ? $claim->{$method}($value)
                : $claim;
        }

        return $claim;
    }
}
