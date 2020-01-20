<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Str;

class JWTGenerateSecretCommand extends Command
{
    /**
     * The console command signature.
     *
     * @var string
     */
    protected $signature = 'jwt:secret
        {--s|show : Display the key instead of modifying files.}
        {--f|force : Skip confirmation when overwriting an existing key.}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Set the secret key used to sign the tokens';

    /**
     * Execute the console command.
     *
     * @return void
     */
    public function handle()
    {
        $key = Str::random(64);

        if ($this->option('show')) {
            $this->comment($key);

            return;
        }

        if (file_exists($path = $this->laravel->environmentFilePath()) === false) {
            return $this->displayKey($key);
        }

        if (Str::contains(file_get_contents($path), 'JWT_SECRET') === false) {
            // update existing entry
            file_put_contents($path, PHP_EOL."JWT_SECRET=$key", FILE_APPEND);
        } else {
            if ($this->isConfirmed() === false) {
                $this->comment('Phew... No changes were made to your secret key.');

                return;
            }

            // create new entry
            file_put_contents($path, str_replace(
                'JWT_SECRET='.$this->laravel['config']['jwt.secret'],
                'JWT_SECRET='.$key, file_get_contents($path)
            ));
        }

        $this->displayKey($key);
    }

    /**
     * Display the key.
     */
    protected function displayKey(string $key): void
    {
        $this->laravel['config']['jwt.secret'] = $key;

        $this->info("jwt-auth secret [$key] set successfully.");
    }

    /**
     * Check if the modification is confirmed.
     */
    protected function isConfirmed(): bool
    {
        return $this->option('force') ? true : $this->confirm(
            'This will invalidate all existing tokens. Are you sure you want to override the secret key?'
        );
    }
}
