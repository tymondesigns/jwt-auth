# jwt-auth

> JSON Web Token Authentication for Laravel

[![Build Status](http://img.shields.io/travis/tymondesigns/jwt-auth.svg?style=flat-square)](https://travis-ci.org/tymondesigns/jwt-auth)
[![Scrutinizer Code Quality](http://img.shields.io/scrutinizer/g/tymondesigns/jwt-auth.svg?style=flat-square)](https://scrutinizer-ci.com/g/tymondesigns/jwt-auth/)
[![Coverage Status](https://img.shields.io/scrutinizer/coverage/g/tymondesigns/jwt-auth.svg?style=flat-square)](https://scrutinizer-ci.com/g/tymondesigns/jwt-auth/code-structure)
[![License](http://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](http://www.opensource.org/licenses/MIT)
[![Latest Version](http://img.shields.io/packagist/v/tymon/jwt-auth.svg?style=flat-square)](https://packagist.org/packages/tymon/jwt-auth)
[![Total Downloads](https://img.shields.io/packagist/dt/tymon/jwt-auth.svg?style=flat-square)](https://packagist.org/packages/tymon/jwt-auth)


#### *Docs work in progress!*

This package requires PHP >=5.4

###### *lots of improvements being made on develop branch (0.4.x-dev). Hope to release soon*

## Installation

Install via composer - edit your `composer.json` to require the package.

```js
"require": {
    "tymon/jwt-auth": "0.3.*"
}
```

Then run `composer update` in your terminal to pull it in.

Once this has finished, you will need to add the service provider to the `providers` array in `app/config/app.php` as follows:

```php
'Tymon\JWTAuth\Providers\JWTAuthServiceProvider'
```

Next, also in the `app/config/app.php` file, under the `aliases` array, you may want to add the `JWTAuth` facade.

```php
'JWTAuth' => 'Tymon\JWTAuth\Facades\JWTAuth'
```

Finally, you will want to publish the config using the following command:

```bash
$ php artisan config:publish tymon/jwt-auth
```

##### **Don't forget to set a secret key in the config file!**

I have included a helper command to generate a key as follows:

```bash
$ php artisan jwt:generate
```

this will generate a new random key, which will be used to sign your tokens.

And you're done!

## Basic Usage

### Creating Tokens

There are a number of ways you can generate a token. The usual flow would be to pass some credentials and the package will try to authenticate the user and return a fully formed JSON Web Token.

##### Authenticating a User

```php
// simple example
Route::post('auth/login', function () {
    $credentials = Input::only('email', 'password');

    if ( ! $token = JWTAuth::attempt($credentials) )
    {
        // return 401 error response
    }

    return Response::json(compact('token'));
});
```

##### Creating a token based on a User object

```php
$user = User::find(1);
$token = JWTAuth::fromUser($user);
```

### Retrieving User from a token

Once a user has "logged in" (e.g. provided their credentials via a login form) to your application, then the next step would be to make a subsequent request, with the token, to retrieve the users' details, so you can show them as being logged in.

To make authenticated requests, you will need to set an authorization header:

`Authorization: Bearer {yourtokenhere}`

Alternatively you can include the token via a query string

`http://api.mysite.com/me?token={yourtokenhere}`

```php
// simple example
Route::post('me', function () {

    try
    {
        $user = JWTAuth::parseToken()->toUser();
    }
    catch(Tymon\JWTAuth\Exceptions\TokenExpiredException $e)
    {
        // token has expired
        return Response::json(['error' => 'token_expired'], 401);
    }

    if (! $user)
    {
        // user not found
        return Response::json(['error' => 'user_not_found'], 404);
    }

    return Response::json(compact('user'));
});

```

Alternatively, you can use the included `jwt-auth` route filter. It includes some sensible default responses when, for example, the token has expired or is invalid.

```php
Route::post('me', ['before' => 'jwt-auth', function() {

    $user = JWTAuth::getToken()->toUser();

    return Response::json(compact('user'));
}]);
```

These responses can be overridden, by hooking into a series of events that are fired before the response is returned. Here are the events that can be fired during the filter.

```php
// fired when the token could not be found in the request
Event::listen('tymon.jwt.absent');

// fired when the token has expired
Event::listen('tymon.jwt.expired');

// fired when the token is found to be invalid
Event::listen('tymon.jwt.invalid');

// fired if the user could not be found (shouldn't really happen)
Event::listen('tymon.jwt.user_not_found');

// fired when the token is valid (User is passed along with event)
Event::listen('tymon.jwt.valid');
```

## API

```php
// accepts an array of credentials e.g. email & password
JWTAuth::attempt($credentials);

// accepts a token and returns the authenticated user on success
JWTAuth::login($token);

// retrieves the token from the request
// (checks Authorization Bearer header and query string)
JWTAuth::getToken();

// accepts a token and returns the User object
JWTAuth::toUser($token);

// accepts a User, and returns a token
JWTAuth::fromUser($user);

// sets the token for the request
// further methods that require a token can then be chained
JWTAuth::setToken($token);

// returns the subject (sub) claim from the token
// (defaults to User id)
JWTAuth::getSubject($token);

// provides access to the underlying jwt provider
// returns a token
JWTAuth::encode($subject, $customClaims);

// decodes a token and returns the payload array
JWTAuth::decode($token);
```
## Todo

- [x] add more tests
- [x] add test coverage reporting
- [ ] finish docs!
- [ ] fully decouple from laravel

## License

The MIT License (MIT)

Copyright (c) 2014 Sean Tymon

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
