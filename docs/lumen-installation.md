### Install via composer

Run the following command to pull in the latest version:

```bash
composer require tymon/jwt-auth
```

-------------------------------------------------------------------------------

### Copy the config

Copy the `config` file from `vendor/tymon/jwt-auth/config/config.php` to `config` folder of your Lumen application and rename it to `jwt.php`

Register your config by adding the following in the `bootstrap/app.php` before middleware declaration.

```php
$app->configure('jwt');
```

-------------------------------------------------------------------------------

### Bootstrap file changes

Add the following snippet to the `bootstrap/app.php` file under the providers section as follows:

```php
// Uncomment this line
$app->register(App\Providers\AuthServiceProvider::class);

// Add this line
$app->register(Tymon\JWTAuth\Providers\LumenServiceProvider::class);
```

Then uncomment the `auth` middleware in the same file:

```php
$app->routeMiddleware([
    'auth' => App\Http\Middleware\Authenticate::class,
]);
```

-------------------------------------------------------------------------------

### Generate secret key

I have included a helper command to generate a key for you:

```bash
php artisan jwt:secret
```

This will update your `.env` file with something like `JWT_SECRET=foobar`

It is the key that will be used to sign your tokens. How that happens exactly will depend
on the algorithm that you choose to use.
