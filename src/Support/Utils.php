<?php declare(strict_types=1);

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Support;

use Carbon\Carbon;

class Utils
{
    /**
     * Get the Carbon instance for the current time.
     *
     */
    public static function now(): \Carbon\Carbon
    {
        return Carbon::now('UTC');
    }

    /**
     * Get the Carbon instance for the timestamp.
     *
     * @param  int  $timestamp
     *
     */
    public static function timestamp(int $timestamp): \Carbon\Carbon
    {
        return Carbon::createFromTimestampUTC($timestamp)->timezone('UTC');
    }

    /**
     * Checks if a timestamp is in the past.
     *
     * @param  int  $timestamp
     *
     */
    public static function isPast(int $timestamp): bool
    {
        return static::timestamp($timestamp)->isPast();
    }

    /**
     * Checks if a timestamp is in the future.
     *
     * @param  int  $timestamp
     *
     */
    public static function isFuture(int $timestamp): bool
    {
        return static::timestamp($timestamp)->isFuture();
    }
}
