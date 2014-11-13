<?php

namespace Tymon\JWTAuth\Test;

use Mockery;
use Symfony\Component\Console\Tester\CommandTester;
use Tymon\JWTAuth\Commands\JWTGenerateCommand;

class JWTGenerateCommandTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->filesystem = Mockery::mock('Illuminate\Filesystem\Filesystem');
        $this->command = new JWTGenerateCommand($this->filesystem);
        $this->tester = new CommandTester($this->command);
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /** @test */
    public function it_shoud_generate_random_key()
    {
        // Mockery::mock('Str')->shouldReceive('random')->andReturn('foo');

        // $this->assertEquals('JWT Auth key [foo] set successfully.\n', $this->tester->getDisplay());
    }

}