<?php

/*
 * This file is part of jwt-auth
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test\Providers\JWT;

use Mockery;
use Tymon\JWTAuth\Providers\JWT\Namshi;

class NamshiTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \Mockery\MockInterface
     */
    protected $jws;

    /**
     * @var \Tymon\JWTAuth\Providers\JWT\Namshi
     */
    protected $provider;

    public function setUp()
    {
        $this->jws = Mockery::mock('Namshi\JOSE\JWS');
        $this->provider = new Namshi('secret', 'HS256', $this->jws);
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /** @test */
    public function it_should_return_the_token_when_passing_a_valid_subject_to_encode()
    {
        $payload = ['sub' => 1, 'exp' => time(), 'iat' => time(), 'iss' => '/foo'];

        $this->jws->shouldReceive('setPayload')->once()->with($payload)->andReturn(Mockery::self());
        $this->jws->shouldReceive('sign')->once()->with('secret')->andReturn(Mockery::self());
        $this->jws->shouldReceive('getTokenString')->once()->andReturn('foo.bar.baz');

        $token = $this->provider->encode($payload);

        $this->assertSame('foo.bar.baz', $token);
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function it_should_throw_an_invalid_exception_when_the_payload_could_not_be_encoded()
    {
        $this->jws->shouldReceive('sign')->andThrow(new \Exception);

        $payload = ['sub' => 1, 'exp' => time(), 'iat' => time(), 'iss' => '/foo'];
        $this->provider->encode($payload);
    }

    /** @test */
    // public function it_should_return_the_payload_when_passing_a_valid_token_to_decode()
    // {
        // $this->jws->shouldReceive('load')->once()->with('foo.bar.baz')->andReturn(true);
        // $this->jws->shouldReceive('verify')->andReturn(true);

        // $payload = $this->provider->decode('foo.bar.baz');

    // }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\TokenInvalidException
     */
    public function it_should_throw_a_token_invalid_exception_when_the_token_could_not_be_decoded()
    {
        $this->jws->shouldReceive('verify')->andReturn(false);

        $this->provider->decode('foo');
    }
}
