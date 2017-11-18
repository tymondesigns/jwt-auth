<?php declare(strict_types=1);

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Contracts\Providers;

interface Storage
{
    /**
     * @param  string  $key
     * @param  mixed  $value
     * @param  int  $minutes
     *
     * @return void
     */
    public function add(string $key, $value, $minutes);

    /**
     * @param  string  $key
     * @param  mixed  $value
     *
     * @return void
     */
    public function forever(string $key, $value);

    /**
     * @param  string  $key
     *
     * @return mixed
     */
    public function get(string $key);

    /**
     * @param  string  $key
     *
     */
    public function destroy(string $key): bool;

    /**
     * @return void
     */
    public function flush();
}
