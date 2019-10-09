<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test\Stubs;

use Cartalyst\Sentinel\Users\UserInterface;
use phpDocumentor\Reflection\Types\String_;

class SentinelStub implements UserInterface
{
    public function getUserId() : int
    {
        return 123;
    }

    public function getUserLogin() : string
    {
        return 'foo';
    }

    public function getUserLoginName() : string
    {
        return 'bar';
    }

    public function getUserPassword() : string
    {
        return 'baz';
    }
}
