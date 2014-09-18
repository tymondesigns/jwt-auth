# jwt-auth

> JSON Web Token Authentication for Laravel

[![Build Status](http://img.shields.io/travis/tymondesigns/jwt-auth.svg?style=flat-square)](https://travis-ci.org/tymondesigns/jwt-auth)
[![Scrutinizer Code Quality](http://img.shields.io/scrutinizer/g/tymondesigns/jwt-auth.svg?style=flat-square)](https://scrutinizer-ci.com/g/tymondesigns/jwt-auth/?branch=master)

## Installation

Install via composer - edit your `composer.json` to require the package.

```js
"require": {
    "tymon/jwt-auth": "~0.*"
}
```

Then run `composer update` in your terminal to pull it in.

Once this has finished, you will need to add the service provider to the `providers` array in `app/config/app.php` as follows:

```php
'Tymon\JWTAuth\JWTAuthServiceProvider'
```

Next, also in the `app/config/app.php` file, under the `aliases` array, you may want to add the `JWTAuth` facade.

```php
'JWTAuth'  =>  'Tymon\JWTAuth\Facades\JWTAuth'
```

Finally, you will want to publish the config using the following command:

```bash
php artisan config:publish tymon/jwt-auth
```

And you're done!

## Usage

More docs coming soon...
