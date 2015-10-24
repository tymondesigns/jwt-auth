<?php

/*
 * This file is part of jwt-auth
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test;

use Mockery;
use Carbon\Carbon;
use Tymon\JWTAuth\Blacklist;
use Tymon\JWTAuth\Payload;
use Tymon\JWTAuth\Claims\Issuer;
use Tymon\JWTAuth\Claims\IssuedAt;
use Tymon\JWTAuth\Claims\Expiration;
use Tymon\JWTAuth\Claims\NotBefore;
use Tymon\JWTAuth\Claims\Audience;
use Tymon\JWTAuth\Claims\Subject;
use Tymon\JWTAuth\Claims\JwtId;
use Tymon\JWTAuth\Claims\Custom;
use Illuminate\Support\Collection;

class BlacklistTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        Carbon::setTestNow(Carbon::createFromTimeStampUTC(123));

        $this->storage = Mockery::mock('Tymon\JWTAuth\Contracts\Providers\Storage');
        $this->blacklist = new Blacklist($this->storage);

        $this->validator = Mockery::mock('Tymon\JWTAuth\Validators\PayloadValidator');
        $this->validator->shouldReceive('setRefreshFlow->check');
    }

    public function tearDown()
    {
        Carbon::setTestNow();
        Mockery::close();
    }

    /** @test */
    public function it_should_add_a_valid_token_to_the_blacklist()
    {
        $claims = [
            'sub' => new Subject(1),
            'iss' => new Issuer('http://example.com'),
            'exp' => new Expiration(123 + 3600),
            'nbf' => new NotBefore(123),
            'iat' => new IssuedAt(123),
            'jti' => new JwtId('foo')
        ];
        $payload = new Payload(Collection::make($claims), $this->validator);

        $this->storage->shouldReceive('add')->with('foo', ['valid_until' => 123], 20161)->once();
        $this->blacklist->add($payload);
    }

    /** @test */
    public function it_should_return_true_when_adding_an_expired_token_to_the_blacklist()
    {
        $claims = [
            'sub' => new Subject(1),
            'iss' => new Issuer('http://example.com'),
            'exp' => new Expiration(123 - 3600),
            'nbf' => new NotBefore(123),
            'iat' => new IssuedAt(123),
            'jti' => new JwtId('foo')
        ];
        $payload = new Payload(Collection::make($claims), $this->validator, true);

        $this->storage->shouldReceive('add')->with('foo', ['valid_until' => 123], 20161)->once();
        $this->assertTrue($this->blacklist->add($payload));
    }

    /** @test */
    public function it_should_check_whether_a_token_has_been_blacklisted()
    {
        $claims = [
            'sub' => new Subject(1),
            'iss' => new Issuer('http://example.com'),
            'exp' => new Expiration(123 + 3600),
            'nbf' => new NotBefore(123),
            'iat' => new IssuedAt(123),
            'jti' => new JwtId('foobar')
        ];
        $payload = new Payload(Collection::make($claims), $this->validator);

        $this->storage->shouldReceive('get')->with('foobar')->once()->andReturn(['valid_until' => 123]);

        $this->assertTrue($this->blacklist->has($payload));
    }

    /** @test */
    public function it_should_check_whether_a_token_has_been_blacklisted_when_the_token_is_not_blacklisted()
    {
        $claims = [
            'sub' => new Subject(1),
            'iss' => new Issuer('http://example.com'),
            'exp' => new Expiration(123 + 3600),
            'nbf' => new NotBefore(123),
            'iat' => new IssuedAt(123),
            'jti' => new JwtId('foobar')
        ];
        $payload = new Payload(Collection::make($claims), $this->validator);

        $this->storage->shouldReceive('get')->with('foobar')->once()->andReturn(null);

        $this->assertFalse($this->blacklist->has($payload));
    }

    /** @test */
    public function it_should_remove_a_token_from_the_blacklist()
    {
        $claims = [
            'sub' => new Subject(1),
            'iss' => new Issuer('http://example.com'),
            'exp' => new Expiration(123 + 3600),
            'nbf' => new NotBefore(123),
            'iat' => new IssuedAt(123),
            'jti' => new JwtId('foobar')
        ];
        $payload = new Payload(Collection::make($claims), $this->validator);

        $this->storage->shouldReceive('destroy')->with('foobar')->andReturn(true);
        $this->assertTrue($this->blacklist->remove($payload));
    }

    /** @test */
    public function it_should_set_a_custom_unique_key_for_the_blacklist()
    {
        $claims = [
            'sub' => new Subject(1),
            'iss' => new Issuer('http://example.com'),
            'exp' => new Expiration(123 + 3600),
            'nbf' => new NotBefore(123),
            'iat' => new IssuedAt(123),
            'jti' => new JwtId('foobar')
        ];
        $payload = new Payload(Collection::make($claims), $this->validator);

        $this->storage->shouldReceive('get')->with(1)->once()->andReturn(['valid_until' => 123]);

        $this->assertTrue($this->blacklist->setKey('sub')->has($payload));
        $this->assertEquals(1, $this->blacklist->getKey($payload));
    }

    /** @test */
    public function it_should_empty_the_blacklist()
    {
        $this->storage->shouldReceive('flush');
        $this->assertTrue($this->blacklist->clear());
    }
}
