<?php

namespace Tymon\JWTAuth\Contracts\Providers;

interface Storage
{
    /**
     * @param  string   $key
     * @param  mixed    $value
     * @param  integer  $minutes
     *
     * @return void
     */
    public function add($key, $value, $minutes);

    /**
     * @param  string  $key
     *
     * @return mixed
     */
    public function get($key);

    /**
     * @param  string  $key
     *
     * @return boolean
     */
    public function destroy($key);

    /**
     * @return void
     */
    public function flush();
}
