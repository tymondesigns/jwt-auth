<?php

namespace Tymon\JWTAuth\Test;

use Mockery;
use Symfony\Component\Console\Tester\CommandTester;
use Tymon\JWTAuth\Commands\JWTGenerateCommand;

class JWTGenerateCommandTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->command = new JWTGenerateCommand();
        $this->tester = new CommandTester($this->command);
    }

    /** @test */
    public function it_shoud_generate_random_key()
    {
        // Mockery::mock('Str')->shouldReceive('random')->andReturn('foo');

        // $this->tester->execute([]);

        // $this->assertEquals('JWT Auth key [foo] set successfully.\n', $this->tester->getDisplay());
    }

}