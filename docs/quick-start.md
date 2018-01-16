Before continuing, make sure you have installed the package as per the installation instructions for
[Laravel](laravel-installation) or [Lumen](lumen-installation).

### Update your User model

Firstly you need to implement the `Tymon\JWTAuth\Contracts\JWTSubject` contract on your User model,
which requires that you implement the 2 methods `getJWTIdentifier()` and `getJWTCustomClaims()`.

The example below should give you an idea of how this could look. Obviously you should make any
changes, as necessary, to suit your own needs.

```php
<?php

namespace App;

use Tymon\JWTAuth\Contracts\JWTSubject;
use Illuminate\Notifications\Notifiable;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable implements JWTSubject
{
    use Notifiable;

    // Rest omitted for brevity

    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return mixed
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims()
    {
        return [];
    }
}
```

### Configure Auth guard

*Note: This will only work if you are using Laravel 5.2 and above.*

Inside the `config/auth.php` file you will need to make a few changes to configure Laravel
to use the `jwt` guard to power your application authentication.

Make the following changes to the file:

```php
'defaults' => [
    'guard' => 'api',
    'passwords' => 'users',
],

...

'guards' => [
    'api' => [
        'driver' => 'jwt',
        'provider' => 'users',
    ],
],
```

Here we are telling the `api` guard to use the `jwt` driver, and we are setting the `api` guard
as the default.

We can now use Laravel's built in Auth system, with jwt-auth doing the work behind the scenes!

### Add some basic authentication routes

First let's add some routes in `routes/api.php` as follows:

```php
Route::group([

    'middleware' => 'api',
    'prefix' => 'auth'

], function ($router) {

    Route::post('login', 'AuthController@login');
    Route::post('logout', 'AuthController@logout');
    Route::post('refresh', 'AuthController@refresh');
    Route::post('me', 'AuthController@me');

});
```

### Create the AuthController

Then create the `AuthController`, either manually or by running the artisan command:

```bash
php artisan make:controller AuthController
```

Then add the following:

```php
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login']]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login()
    {
        $credentials = request(['email', 'password']);

        if (! $token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }
}
```

You should now be able to POST to the login endpoint (e.g. `http://example.dev/auth/login`) with some valid
credentials and see a response like:

```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ",
    "token_type": "bearer",
    "expires_in": 3600
}
```

This token can then be used to make authenticated requests to your application.

### Authenticated requests

There are a number of ways to send the token via http:

**Authorization header**

`Authorization: Bearer eyJhbGciOiJIUzI1NiI...`

**Query string parameter**

`http://example.dev/me?token=eyJhbGciOiJIUzI1NiI...`

**Post parameter**

**Cookies**

**Laravel route parameter**
