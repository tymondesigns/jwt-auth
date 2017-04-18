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

use Carbon\Carbon;

class Utils
{
    /**
     * Get the Carbon instance for the current time.
     *
     * @return \Carbon\Carbon
     */
    public static function now()
    {
        return Carbon::now();
    }

    /**
     * Get the Carbon instance for the timestamp.
     *
     * @param  int  $timestamp
     * @return \Carbon\Carbon
     */
    public static function timestamp($timestamp)
    {
        //This causes problems on our version of PHP
        //return Carbon::createFromTimeStampUTC($timestamp);
        
        // This is good for our version of PHP and doesn't seem to 
        // affect the output of the package
        return Carbon::createFromTimeStamp($timestamp, 'UTC’);
    }
}
