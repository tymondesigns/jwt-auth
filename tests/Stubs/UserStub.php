<?php declare(strict_types=1);

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test\Stubs;

use Tymon\JWTAuth\Contracts\JWTSubject;

class UserStub implements JWTSubject
{
    public function getJWTIdentifier()
    {
        return 1;
    }

    public function getJWTCustomClaims(): array
    {
        return [
            'foo' => 'bar',
            'role' => 'admin',
        ];
    }
}
