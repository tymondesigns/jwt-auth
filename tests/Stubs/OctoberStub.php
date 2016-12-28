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

use October\Rain\Auth\Models\User as UserModel;

class OctoberStub extends UserModel
{
    public function getId()
    {
        return 123;
    }
}
