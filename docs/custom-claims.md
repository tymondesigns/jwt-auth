### Custom Claims

Instead of using auth claims / or claims for specific entity, you can use the custom claims.

For encoding
```
$payload = \Tymon\JWTAuth\Facades\JWTFactory::claims($claims)->make()
$token = \Tymon\JWTAuth\Facades\JWTAuth::encode($payload);
```

For decoding
```
$payload = \Tymon\JWTAuth\Facades\JWTAuth::setToken($payload)->getPayload()
```
