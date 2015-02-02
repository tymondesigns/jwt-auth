<?php

namespace Tymon\JWTAuth;

use Carbon\Carbon;

class Utils
{
    /**
     * Get the Carbon instance for the current time
     *
     * @return \Carbon\Carbon
     */
    public static function now()
    {
        return Carbon::now();
    }

    /**
     * Get the Carbon instance for the timestamp
     *
     * @param  int  $timestamp
     * @return \Carbon\Carbon
     */
    public static function timestamp($timestamp)
    {
        return Carbon::createFromTimeStampUTC($timestamp);
    }
}
