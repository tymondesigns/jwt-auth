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

use Carbon\Carbon;
use Mockery;
use Tymon\JWTAuth\Blacklist;
use Tymon\JWTAuth\Payload;
use Tymon\JWTAuth\Claims\Issuer;
use Tymon\JWTAuth\Claims\IssuedAt;
use Tymon\JWTAuth\Claims\Expiration;
use Tymon\JWTAuth\Claims\NotBefore;
use Tymon\JWTAuth\Claims\Subject;
use Tymon\JWTAuth\Claims\JwtId;

class BlacklistTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        Carbon::setTestNow(Carbon::createFromTimeStampUTC(123));

        $this->storage = Mockery::mock('Tymon\JWTAuth\Providers\Storage\StorageInterface');
        $this->blacklist = new Blacklist($this->storage);
        $this->blacklist->setRefreshTTL(20160);

        $this->validator = Mockery::mock('Tymon\JWTAuth\Validators\PayloadValidator');
        $this->validator->shouldReceive('setRefreshFlow->check');
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /** @test */
    public function it_should_add_a_valid_token_to_the_blacklist()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration(100 + 3600),
            new NotBefore(100),
            new IssuedAt(100),
            new JwtId('foo'),
        ];
        $payload = new Payload($claims, $this->validator);

        $this->storage->shouldReceive('add')->once()->with('foo', [], 20160);
        $this->assertTrue($this->blacklist->add($payload));
    }

    /** @test */
    public function it_should_return_true_when_adding_a_refreshable_expired_token_to_the_blacklist()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration(101),
            new NotBefore(100),
            new IssuedAt(100),
            new JwtId('foo'),
        ];
        $payload = new Payload($claims, $this->validator, true);

        $this->storage->shouldReceive('add')->once()->with('foo', [], 20160);
        $this->assertTrue($this->blacklist->add($payload));
    }

    /** @test */
    public function it_should_return_false_when_adding_an_unrefreshable_token_to_the_blacklist()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration(100), // default refresh_ttl
            new NotBefore(100),
            new IssuedAt(100 - 20160 * 60),
            new JwtId('foo'),
        ];
        $payload = new Payload($claims, $this->validator, true);

        $this->storage->shouldReceive('add')->never();
        $this->assertFalse($this->blacklist->add($payload));
    }

    /** @test */
    public function it_should_return_false_when_adding_a_unrefreshable_token_after_modifying_refresh_ttl()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration(101),
            new NotBefore(100),
            new IssuedAt(100),
            new JwtId('foo'),
        ];
        $payload = new Payload($claims, $this->validator, true);

        $this->storage->shouldReceive('add')->never();
        $this->blacklist->setRefreshTTL(0);
        $this->assertFalse($this->blacklist->add($payload));
    }

    /** @test */
    public function it_should_check_whether_a_token_has_been_blacklisted()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration(123 + 3600),
            new NotBefore(123),
            new IssuedAt(123),
            new JwtId('foobar'),
        ];
        $payload = new Payload($claims, $this->validator);

        $this->storage->shouldReceive('has')->once()->with('foobar')->andReturn(true);
        $this->assertTrue($this->blacklist->has($payload));
    }

    /** @test */
    public function it_should_remove_a_token_from_the_blacklist()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration(123 + 3600),
            new NotBefore(123),
            new IssuedAt(123),
            new JwtId('foobar'),
        ];
        $payload = new Payload($claims, $this->validator);

        $this->storage->shouldReceive('destroy')->once()->with('foobar')->andReturn(true);
        $this->assertTrue($this->blacklist->remove($payload));
    }

    /** @test */
    public function it_should_empty_the_blacklist()
    {
        $this->storage->shouldReceive('flush')->once();
        $this->assertTrue($this->blacklist->clear());
    }
}
