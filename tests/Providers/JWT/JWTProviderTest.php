<?php

namespace Tymon\JWTAuth\Test\Providers\JWT;

use Mockery;
use Illuminate\Http\Request;
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
