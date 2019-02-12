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

namespace Tymon\JWTAuth\Support;

use Carbon\Carbon;

/**
 * Get the Carbon instance for the current time.
 */
function now()
{
    return Carbon::now('UTC');
}

/**
 * Get the Carbon instance for the timestamp.
 */
function timestamp(int $timestamp): Carbon
{
    return Carbon::createFromTimestampUTC($timestamp)
        ->timezone('UTC');
}

/**
 * Checks if a timestamp is in the past.
 */
function is_past(int $timestamp, int $leeway = 0): bool
{
    return timestamp($timestamp)
        ->addSeconds($leeway)
        ->isPast();
}

/**
 * Checks if a timestamp is in the future.
 */
function is_future(int $timestamp, int $leeway = 0): bool
{
    return timestamp($timestamp)
        ->subSeconds($leeway)
        ->isFuture();
}
