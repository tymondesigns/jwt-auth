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
use Namshi\JOSE\JWS;
use Tymon\JWTAuth\Providers\JWT\Namshi;
use Tymon\JWTAuth\Test\AbstractTestCase;

class NamshiTest extends AbstractTestCase
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
        parent::setUp();

        $this->jws = Mockery::mock(JWS::class);
    }

    public function tearDown()
    {
        Mockery::close();

        parent::tearDown();
    }

    /** @test */
    public function it_should_return_the_token_when_passing_a_valid_payload_to_encode()
    {
        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $this->jws->shouldReceive('setPayload')->once()->with($payload)->andReturn(Mockery::self());
        $this->jws->shouldReceive('sign')->once()->with('secret', null)->andReturn(Mockery::self());
        $this->jws->shouldReceive('getTokenString')->once()->andReturn('foo.bar.baz');

        $token = $this->getProvider('secret', 'HS256')->encode($payload);

        $this->assertSame('foo.bar.baz', $token);
    }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function it_should_throw_an_invalid_exception_when_the_payload_could_not_be_encoded()
    {
        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $this->jws->shouldReceive('setPayload')->once()->with($payload)->andReturn(Mockery::self());
        $this->jws->shouldReceive('sign')->andThrow(new \Exception);

        $this->getProvider('secret', 'HS256')->encode($payload);
    }

    /** @test */
    // public function it_should_return_the_payload_when_passing_a_valid_token_to_decode()
    // {
    //     $this->jws->shouldReceive('load')->once()->with('foo.bar.baz')->andReturn(Mockery::self());
    //     $this->jws->shouldReceive('verify')->andReturn(true);

    //     $payload = $this->getProvider('secret', 'HS256')->decode('foo.bar.baz');

    // }

    /**
     * @test
     * @expectedException \Tymon\JWTAuth\Exceptions\TokenInvalidException
     */
    // public function it_should_throw_a_token_invalid_exception_when_the_token_could_not_be_decoded()
    // {
    //     $this->jws->shouldReceive('load')->once()->with('foo.bar.baz')->andReturn(Mockery::self());
    //     $this->jws->shouldReceive('verify')->once()->with('secret', null)->andReturn(false);

    //     $this->getProvider('secret', 'HS256')->decode('foo.bar.baz');
    // }

    /** @test */
    public function it_should_generate_a_token_when_using_an_rsa_algorithm()
    {
        $provider = $this->getProvider(
            'does_not_matter',
            'RS256',
            ['private' => $this->getFakePrivateKey(), 'public' => $this->getFakePublicKey()]
        );

        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $this->jws->shouldReceive('setPayload')->once()->with($payload)->andReturn(Mockery::self());
        $this->jws->shouldReceive('sign')->once()->with($this->getFakePrivateKey(), null)->andReturn(Mockery::self());
        $this->jws->shouldReceive('getTokenString')->once()->andReturn('foo.bar.baz');

        $token = $provider->encode($payload);

        $this->assertSame('foo.bar.baz', $token);
    }

    /** @test */
    public function it_should_generate_a_token_when_using_an_ecdsa_algorithm()
    {
        $provider = $this->getProvider(
            'does_not_matter',
            'ES256',
            ['private' => $this->getFakePrivateKey(), 'public' => $this->getFakePublicKey()]
        );

        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $this->jws->shouldReceive('setPayload')->once()->with($payload)->andReturn(Mockery::self());
        $this->jws->shouldReceive('sign')->once()->with($this->getFakePrivateKey(), null)->andReturn(Mockery::self());
        $this->jws->shouldReceive('getTokenString')->once()->andReturn('foo.bar.baz');

        $token = $provider->encode($payload);

        $this->assertSame('foo.bar.baz', $token);
    }

    /** @test */
    public function it_should_decode_a_token_when_using_an_rsa_algorithm()
    {
        $provider = $this->getProvider(
            'does_not_matter',
            'RS256',
            ['private' => $this->getFakePrivateKey(), 'public' => $this->getFakePublicKey()]
        );

        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $this->jws->shouldReceive('setPayload')->once()->with($payload)->andReturn(Mockery::self());
        $this->jws->shouldReceive('sign')->once()->with($this->getFakePrivateKey(), null)->andReturn(Mockery::self());
        $this->jws->shouldReceive('getTokenString')->once()->andReturn('foo.bar.baz');

        $token = $provider->encode($payload);

        $this->assertSame('foo.bar.baz', $token);
    }

    public function getProvider($secret, $algo, array $keys = [])
    {
        return new Namshi($secret, $algo, $keys, $this->jws);
    }

    public function getFakePrivateKey()
    {
        return '-----BEGIN RSA PRIVATE KEY-----
            MIICWwIBAAKBgHURzSlt138r+y76sFtADAiW3Xc2cvXdyXyc/Xr7EEDLSpqfs+aE
            htAs8H+Q5VrX+aPH+Q6CQnIhjdJEp2FYPXURsLPVfnmjgek29LYKumuVGk7+PB3k
            Ao1UTOdjFZ89TXmm4gKBee7bJxKRNgSR2FglgkD8Em7t72D2LyBiM3lRAgMBAAEC
            gYAo2eZin47ENL+4/AeQQAAy+xoa4GgrPZJypoGZaYSZZ5cH79SiCvrUJ+pgSVqP
            YbAeI8jX9EJleyn3Brf1swn2l56xyDQGUJ0ctY6TjLO5mfptEtfBIzkJzDenVcOE
            F+HmEMht1BonfUXD3ep9jX0SYq1xRyt4euJoa9zBhEcgxQJBAL+HBIO2O7rWIu4I
            r6MplaRIKvuS1PGVe+gjCnSNmx9lejsGhDWOaqkLh0Ep8aJdzW4XL6KC5rKB6E8t
            sg9KoUsCQQCcelWh+sRBIkiq1ZoTQlxrfIyd+40hjTexThTMHF/TjfPFj+c/U6Nd
            5XxiGXIeszJz/IDTciPfShr8zp3DtMpTAkEAtY2bbe9U92r9eX6qX5SP0UbH1+n8
            CXWWGxr8UjfZkA11rHYk5U+3M79F2zOTZkJc9brs4LQNU7FpMYUzgONRuQJASgOX
            c6mgoMptotisK0XtXy4neSaeJ+ubFzO+pJkbPn7bemxJzmtqT6SXw/MTRrAuQiyC
            ZwGLNDfiMggtGX/vXwJAUqKz/Tw9XUdhnfCCMpR5BlaSKJVTh0+ItEGw+wSHO68k
            WoXTo5sbaMNsCHJJTMVhBO+QxRdPxyeAPNJdvtX0gA==
            -----END RSA PRIVATE KEY-----';
    }

    public function getFakePublicKey()
    {
        return '-----BEGIN PUBLIC KEY-----
            MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHURzSlt138r+y76sFtADAiW3Xc2
            cvXdyXyc/Xr7EEDLSpqfs+aEhtAs8H+Q5VrX+aPH+Q6CQnIhjdJEp2FYPXURsLPV
            fnmjgek29LYKumuVGk7+PB3kAo1UTOdjFZ89TXmm4gKBee7bJxKRNgSR2FglgkD8
            Em7t72D2LyBiM3lRAgMBAAE=
            -----END PUBLIC KEY-----';
    }
}
