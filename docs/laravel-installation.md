### Install via composer

Run the following command to pull in the latest version:

```bash
composer require tymon/jwt-auth
```

-------------------------------------------------------------------------------

### Add service provider ( Laravel 5.4 or below )

Add the service provider to the `providers` array in the `config/app.php` config file as follows:

```php
'providers' => [

    ...

    Tymon\JWTAuth\Providers\LaravelServiceProvider::class,
]
```

-------------------------------------------------------------------------------

### Publish the config

Run the following command to publish the package config file:

```bash
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
```

You should now have a `config/jwt.php` file that allows you to configure the basics of this package.

-------------------------------------------------------------------------------

### Generate secret key

I have included a helper command to generate a key for you:

```bash
php artisan jwt:secret
```

This will update your `.env` file with something like `JWT_SECRET=foobar`

It is the key that will be used to sign your tokens. How that happens exactly will depend
on the algorithm that you choose to use.
