<?php

namespace Tymon\JWTAuth\Test;

use Mockery;
use Symfony\Component\Console\Tester\CommandTester;
use Tymon\JWTAuth\Commands\JWTGenerateCommand;
use Illuminate\Foundation\Application;
use Symfony\Component\Console\Output\NullOutput;
use Symfony\Component\Console\Input\ArrayInput;

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
        // $app = new Application();

        // $app['path.base'] = '';

        // $this->command->setLaravel($app);

        // $this->runCommand($this->command);
    }

    protected function runCommand($command, $input = array())
    {
        return $command->run(new ArrayInput($input), new NullOutput);
    }
}
