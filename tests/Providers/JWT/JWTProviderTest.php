<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test\Providers\JWT;

use Mockery;
use Tymon\JWTAuth\Test\Stubs\JWTProviderStub;

class JWTProviderTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->provider = new JWTProviderStub('secret', 'HS256');
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /** @test */
    public function it_should_set_the_algo()
    {
        $this->provider->setAlgo('HS512');

        $this->assertEquals('HS512', $this->provider->getAlgo());
    }
}
