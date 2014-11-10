<?php

namespace Tymon\JWTAuth\Test\Providers\User;

use Mockery;
use Tymon\JWTAuth\Providers\User\EloquentUserAdapter;

class EloquentUserAdapterTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->model = Mockery::mock('Illuminate\Database\Eloquent\Model');
        $this->user = new EloquentUserAdapter($this->model);
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /** @test */
    public function it_should_return_the_user_if_found()
    {
        // $this->model->shouldReceive('where')->once()->with('foo', 'bar')->andReturn((object) ['id' => 1]);
        // $this->assertEquals($this->user->getBy('foo', 'bar')->id, 1);
    }

}