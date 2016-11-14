<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Providers\Storage;

interface StorageInterface
{
    /**
     * @param string $key
     * @param int $minutes
     * @return void
     */
    public function add($key, $value, $minutes);

    /**
     * @param string $key
     * @return bool
     */
    public function has($key);

    /**
     * @param string $key
     * @return bool
     */
    public function destroy($key);

    /**
     * @return void
     */
    public function flush();
}
