<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Commands;

use Illuminate\Support\Str;
use Illuminate\Console\Command;
use Symfony\Component\Console\Input\InputOption;

class JWTGenerateCommand extends Command
{
    /**
     * The console command name.
     *
     * @var string
     */
    protected $name = 'jwt:generate';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Set the JWTAuth secret key used to sign the tokens';

    /**
     * Execute the console command.
     *
     * @return void
     */
    public function fire()
    {
        $key = $this->getRandomKey();

        if ($this->option('show')) {
            return $this->line('<comment>'.$key.'</comment>');
        }

        $currentKey = $this->laravel['config']['jwt.secret'];
        if (!preg_match('/^JWT_SECRET\=/m', file_get_contents($this->laravel->environmentFilePath()))) {
            file_put_contents($this->laravel->environmentFilePath(),
                file_get_contents($this->laravel->environmentFilePath()) . PHP_EOL . 'JWT_SECRET='.$key
            );
        } else {
            file_put_contents($this->laravel->environmentFilePath(), preg_replace(
                "/^JWT_SECRET" . preg_quote('='.$this->laravel['config']['jwt.secret'], '/') . "/m",
                'JWT_SECRET='.$key,
                file_get_contents($this->laravel->environmentFilePath())
            ));
        }

        $this->laravel['config']['jwt.secret'] = $key;

        $this->info("jwt-auth secret [$key] set successfully.");
    }

    /**
     * Execute the console command.
     *
     * @return void
     */
    public function handle()
    {
        return $this->fire();
    }

    /**
     * Generate a random key for the JWT Auth secret.
     *
     * @return string
     */
    protected function getRandomKey()
    {
        return Str::random(32);
    }

    /**
     * Get the console command options.
     *
     * @return array
     */
    protected function getOptions()
    {
        return [
            ['show', null, InputOption::VALUE_NONE, 'Simply display the key instead of modifying files.'],
        ];
    }
}
