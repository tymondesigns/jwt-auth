## Methods

The following methods are available on the Auth guard instance.

### Multiple Guards

If the newly created 'api' guard is not set as a default guard or you have defined multiple guards to handle authentication,
you should specify the guard when calling Auth::guard().

```php
  $token = Auth::guard('api')->attempt($credentials);
```

### attempt()

Attempt to authenticate a user via some credentials.

```php
// Generate a token for the user if the credentials are valid
$token = Auth::guard()->attempt($credentials);
```

This will return either a jwt or `null`

### login()

Log a user in and return a jwt for them.

```php
// Get some user from somewhere
$user = User::first();

// Get the token
$token = Auth::guard()->login($user);
```

### user()

Get the currently authenticated user.

```php
// Get the currently authenticated user
$user = Auth::guard()->user();
```

If the user is not then authenticated, then `null` will be returned.

### userOrFail()

Get the currently authenticated user or throw an exception.

```php
try {
    $user = Auth::guard()->userOrFail();
} catch (\Tymon\JWTAuth\Exceptions\UserNotDefinedException $e) {
    // do something
}

```

If the user is not set, then a `Tymon\JWTAuth\Exceptions\UserNotDefinedException` will be thrown

### logout()

Log the user out - which will invalidate the current token and unset the authenticated user.

```php
Auth::guard()->logout();

// Pass true to force the token to be blacklisted "forever"
Auth::guard()->logout(true);
```

### refresh()

Refresh a token, which invalidates the current one

```php
$newToken = Auth::guard()->refresh();

// Pass true as the first param to force the token to be blacklisted "forever".
// The second parameter will reset the claims for the new token
$newToken = Auth::guard()->refresh(true, true);
```

### invalidate()

Invalidate the token (add it to the blacklist)

```php
Auth::guard()->invalidate();

// Pass true as the first param to force the token to be blacklisted "forever".
Auth::guard()->invalidate(true);
```

### tokenById()

Get a token based on a given user's id.

```php
$token = Auth::guard()->tokenById(123);
```

### payload()

Get the raw JWT payload

```php
$payload = Auth::guard()->payload();

// then you can access the claims directly e.g.
$payload->get('sub'); // = 123
$payload['jti']; // = 'asfe4fq434asdf'
$payload('exp') // = 123456
$payload->toArray(); // = ['sub' => 123, 'exp' => 123456, 'jti' => 'asfe4fq434asdf'] etc
```

### validate()

Validate a user's credentials

```php
if (Auth::guard()->validate($credentials)) {
    // credentials are valid
}
```

## More advanced usage

### Adding custom claims

```php
$token = Auth::guard()->claims(['foo' => 'bar'])->attempt($credentials);
```

### Set the token explicitly

```php
$user = Auth::guard()->setToken('eyJhb...')->user();
```

### Set the request instance explicitly

```php
$user = Auth::guard()->setRequest($request)->user();
```

### Override the token ttl

```php
$token = Auth::guard()->setTTL(7200)->attempt($credentials);
```
