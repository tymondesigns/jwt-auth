<?php

namespace Tymon\JWTAuth\Commands;

use Illuminate\Console\Command;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Str;

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
    protected $description = "Set the JWT Auth secret key used to sign the tokens";

    /**
     * @var \Illuminate\Filesystem\Filesystem
     */
    protected $files;

    /**
     * Create a new JWT secret generator command.
     *
     * @param  \Illuminate\Filesystem\Filesystem  $files
     */
    public function __construct(Filesystem $files)
    {
        parent::__construct();

        $this->files = $files;
    }

    /**
     * Execute the console command.
     *
     * @return void
     */
    public function fire()
    {
        list($path, $contents) = $this->getKeyFile();

        $key = $this->getRandomKey();

        $contents = str_replace($this->laravel['config']['jwt::secret'], $key, $contents);

        $this->files->put($path, $contents);

        $this->laravel['config']['jwt::secret'] = $key;

        $this->info("JWT Auth key [$key] set successfully.");
    }

    /**
     * Get the key file and contents.
     *
     * @return string[]
     */
    protected function getKeyFile()
    {
        $env = $this->option('env') ? $this->option('env').'/' : '';

        $contents = $this->files->get($path = $this->laravel['path']."/config/packages/tymon/jwt-auth/{$env}config.php");

        return [$path, $contents];
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
}
