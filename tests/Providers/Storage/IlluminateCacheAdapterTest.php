<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test\Providers\Storage;

use Mockery;
use Tymon\JWTAuth\Providers\Storage\IlluminateCacheAdapter;

class IlluminateCacheAdapterTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->cache = Mockery::mock('Illuminate\Cache\CacheManager');
        $this->storage = new IlluminateCacheAdapter($this->cache);

        $this->cache->shouldReceive('tags')->andReturn(Mockery::self());
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /** @test */
    public function it_should_add_the_item_to_storage()
    {
        $this->cache->shouldReceive('tags->put')->with('foo', 'bar', 10);

        $this->storage->add('foo', 'bar', 10);
    }

    /** @test */
    public function it_should_check_if_the_item_exists_in_storage()
    {
        $this->cache->shouldReceive('tags->has')->with('foo')->andReturn(true);

        $this->assertTrue($this->storage->has('foo'));
    }

    /** @test */
    public function it_should_remove_the_item_from_storage()
    {
        $this->cache->shouldReceive('tags->forget')->with('foo')->andReturn(true);

        $this->assertTrue($this->storage->destroy('foo'));
    }

    /** @test */
    public function it_should_remove_all_items_from_storage()
    {
        $this->cache->shouldReceive('tags->flush')->withNoArgs();

        $this->storage->flush();
    }
}
