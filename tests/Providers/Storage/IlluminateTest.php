<?php

/*
 * This file is part of jwt-auth
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test\Providers\Storage;

use Mockery;
use Tymon\JWTAuth\Providers\Storage\Illuminate as Storage;

class TaggedStorage extends Storage {
    // It's extremely challenging to test the actual functionality of the provider's
    // cache() function, because it relies on calling method_exists on methods that
    // aren't defined in the interface. Getting those conditionals to behave as expected
    // would be a lot of finicky work compared to verifying their functionality by hand.
    // So instead we'll just set this value manually...
    protected $supportsTags = true;
}

class IlluminateTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->cache = Mockery::mock('Illuminate\Contracts\Cache\Repository');
        $this->storage = new Storage($this->cache);
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /** @test */
    public function it_should_add_the_item_to_storage()
    {
        $this->cache->shouldReceive('put')->with('foo', 'bar', 10)->once();

        $this->storage->add('foo', 'bar', 10);
    }

    /** @test */
    public function it_should_add_the_item_to_storage_forever()
    {
        $this->cache->shouldReceive('forever')->with('foo', 'bar')->once();

        $this->storage->forever('foo', 'bar');
    }

    /** @test */
    public function it_should_get_an_item_from_storage()
    {
        $this->cache->shouldReceive('get')->with('foo')->once()->andReturn(['foo' => 'bar']);

        $this->assertEquals(['foo' => 'bar'], $this->storage->get('foo'));
    }

    /** @test */
    public function it_should_remove_the_item_from_storage()
    {
        $this->cache->shouldReceive('forget')->with('foo')->once()->andReturn(true);

        $this->assertTrue($this->storage->destroy('foo'));
    }

    /** @test */
    public function it_should_remove_all_items_from_storage()
    {
        $this->cache->shouldReceive('flush')->withNoArgs()->once();

        $this->storage->flush();
    }

    // Duplicate tests for tagged storage --------------------

    /**
     * Replace the storage with our one above that overrides the tag flag, and
     * define expectations for tags() method.
     *
     * @return void
     */
    private function emulateTags()
    {
        $this->storage = new TaggedStorage($this->cache);

        $this->cache->shouldReceive('tags')->with('tymon.jwt')->once()->andReturn(Mockery::self());
    }

        /** @test */
    public function it_should_add_the_item_to_tagged_storage()
    {
        $this->emulateTags();
        $this->cache->shouldReceive('put')->with('foo', 'bar', 10)->once();

        $this->storage->add('foo', 'bar', 10);
    }

    /** @test */
    public function it_should_add_the_item_to_tagged_storage_forever()
    {
        $this->emulateTags();
        $this->cache->shouldReceive('forever')->with('foo', 'bar')->once();

        $this->storage->forever('foo', 'bar');
    }

    /** @test */
    public function it_should_get_an_item_from_tagged_storage()
    {
        $this->emulateTags();
        $this->cache->shouldReceive('get')->with('foo')->once()->andReturn(['foo' => 'bar']);

        $this->assertEquals(['foo' => 'bar'], $this->storage->get('foo'));
    }

    /** @test */
    public function it_should_remove_the_item_from_tagged_storage()
    {
        $this->emulateTags();
        $this->cache->shouldReceive('forget')->with('foo')->once()->andReturn(true);

        $this->assertTrue($this->storage->destroy('foo'));
    }

    /** @test */
    public function it_should_remove_all_tagged_items_from_storage()
    {
        $this->emulateTags();
        $this->cache->shouldReceive('flush')->withNoArgs()->once();

        $this->storage->flush();
    }
}
