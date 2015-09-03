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
use Illuminate\Http\Request;
use Tymon\JWTAuth\Providers\JWT\Namshi;

class NamshiTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->jws = Mockery::mock('Namshi\JOSE\JWS');
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /** @test */
    public function it_should_return_the_token_when_passing_a_valid_subject_to_encode()
    {
        $provider = $this->setupProvider();

        $payload = ['sub' => 1, 'exp' => time(), 'iat' => time(), 'iss' => '/foo'];

        $this->jws->shouldReceive('setPayload')->once()->with($payload)->andReturn(Mockery::self());
        $this->jws->shouldReceive('sign')->once()->with('secret')->andReturn(Mockery::self());
        $this->jws->shouldReceive('getTokenString')->once()->andReturn('foo.bar.baz');

        $token = $provider->encode($payload);

        $this->assertEquals('foo.bar.baz', $token);
    }

    /** @test */
    public function it_should_throw_an_invalid_exception_when_the_payload_could_not_be_encoded()
    {
        $provider = $this->setupProvider();

        $this->setExpectedException('Tymon\JWTAuth\Exceptions\JWTException');

        $this->jws->shouldReceive('sign')->andThrow(new \Exception);

        $payload = ['sub' => 1, 'exp' => time(), 'iat' => time(), 'iss' => '/foo'];
        $token = $provider->encode($payload);
    }

    /** @test */
    // public function it_should_return_the_payload_when_passing_a_valid_token_to_decode()
    // {
        // $this->jws->shouldReceive('load')->once()->with('foo.bar.baz')->andReturn(true);
        // $this->jws->shouldReceive('verify')->andReturn(true);

        // $payload = $this->provider->decode('foo.bar.baz');

    // }

    /** @test */
    public function it_should_throw_a_token_invalid_exception_when_the_token_could_not_be_decoded()
    {
        $provider = $this->setupProvider();

        $this->setExpectedException('Tymon\JWTAuth\Exceptions\TokenInvalidException');

        $this->jws->shouldReceive('verify')->andReturn(false);

        $token = $provider->decode('foo');
    }

    /** @test */
    public function it_should_decode_a_rs256_encoded_payload()
    {
        $provider = $this->setupProvider('secret', 'RS256');

        $payload = ['sub' => 1, 'exp' => time(), 'iat' => time(), 'iss' => '/foo'];

        $this->jws->shouldReceive('setPayload')->once()->with($payload)->andReturn(Mockery::self());
        $this->jws->shouldReceive('sign')->once()->with('secret')->andReturn(Mockery::self());
        $this->jws->shouldReceive('getTokenString')->once()->andReturn('foo.bar.baz');

        $token = $provider->encode($payload);

        $this->assertEquals('foo.bar.baz', $token);
    }

    /** @test */
    public function it_should_decode_a_rs256_encoded_payload_using_cert_instead_of_secret()
    {
        $cert = "-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgH6CGUWwjyuF4JOwQeFcA0s3kuK6
lTqwmTBbZLCyKK3Gmz1iG0vvZTF6lK46A5JOxVffzTYkQ3ZBSaxuTbDxdwgOIb5M
yRU0tyibBgSrOijeCWvR5yk1ypZ5WC3djLHTHOIj2vtLWTYruLxLGzlS5/6u2CCn
mrn+4JBmFCac2yEBAgMBAAE=
-----END PUBLIC KEY-----";

        $provider = $this->setupProvider('secret', 'RS256', $cert);

        $jws = Mockery::mock('Namshi\JOSE\JWS');

        $this->jws->shouldReceive('load')->once()->with('foo', false)->andReturn($jws);
        $jws->shouldReceive('verify')->with($cert, 'RS256')->andReturn(true);
        $jws->shouldReceive('getPayload')->andReturn(null);

        $token = $provider->decode('foo');
    }

    public function setupProvider($secret=null, $algo=null, $cert=null, $jws=null)
    {
        return new Namshi($secret ?: 'secret', $algo ?: 'HS256', $cert ?: null, $jws ?: $this->jws);
    }
}
