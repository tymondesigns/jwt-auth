<?php

namespace Tymon\JWTAuth\Test\Providers\JWT;

use Carbon\Carbon;
use Mockery;
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

class BlacklistTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->storage = Mockery::mock('Tymon\JWTAuth\Providers\Storage\StorageInterface');
        $this->blacklist = new Blacklist($this->storage);

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
            new Expiration(time() + 3600),
            new NotBefore(time()),
            new IssuedAt(time()),
            new JwtId('foo')
        ];
        $payload = new Payload($claims, $this->validator);

        $this->storage->shouldReceive('add')->once();
        $this->blacklist->add($payload);
    }

    /** @test */
    public function it_should_return_false_when_adding_an_expired_token_to_the_blacklist()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration(time() - 3600),
            new NotBefore(time()),
            new IssuedAt(time()),
            new JwtId('foo')
        ];
        $payload = new Payload($claims, $this->validator, true);

        $this->storage->shouldReceive('add')->never();
        $this->assertFalse($this->blacklist->add($payload));
    }

    /** @test */
    public function it_should_check_whether_a_token_has_been_blacklisted()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration(time() + 3600),
            new NotBefore(time()),
            new IssuedAt(time()),
            new JwtId('foobar')
        ];
        $payload = new Payload($claims, $this->validator);

        $this->storage->shouldReceive('get')->once()->with('foobar')->andReturn(['valid_until' => 0]);
        $this->assertTrue($this->blacklist->has($payload));

        $this->storage->shouldReceive('get')->once()->with('foobar')->andReturn(null);
        $this->assertFalse($this->blacklist->has($payload));

        $this->storage->shouldReceive('get')->once()->with('foobar')->andReturn(['valid_until' => time() + 500]);
        $this->assertFalse($this->blacklist->has($payload));
    }

    /** @test */
    public function it_should_remove_a_token_from_the_blacklist()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration(time() + 3600),
            new NotBefore(time()),
            new IssuedAt(time()),
            new JwtId('foobar')
        ];
        $payload = new Payload($claims, $this->validator);

        $this->storage->shouldReceive('destroy')->with('foobar')->andReturn(true);
        $this->assertTrue($this->blacklist->remove($payload));
    }

    /** @test */
    public function it_should_empty_the_blacklist()
    {
        $this->storage->shouldReceive('flush');
        $this->assertTrue($this->blacklist->clear());
    }
}
