<?php

return [

    /*
    |--------------------------------------------------------------------------
    | JWT Authentication Secret
    |--------------------------------------------------------------------------
    |
    | Don't forget to set this, as it will be used to sign your tokens.
    | A helper command is provided for this: `php artisan jwt:generate`
    |
    */

    'secret' => env('JWT_SECRET', 'changeme'),

    /*
    |--------------------------------------------------------------------------
    | JWT time to live
    |--------------------------------------------------------------------------
    |
    | Specify the length of time (in minutes) that the token will be valid for.
    | Set "null" for unlimited.
    | Defaults to 1 hour
    |
    */

    'ttl' => 60,

    /*
    |--------------------------------------------------------------------------
    | Refresh time to live
    |--------------------------------------------------------------------------
    |
    | Specify the length of time (in minutes) that the token can be refreshed
    | within. I.E. The user can refresh their token within a 2 week window of
    | the original token being created until they must re-authenticate.
    | Set "null" for unlimited.
    | Defaults to 2 weeks
    |
    */

    'refresh_ttl' => 20160,

    /*
    |--------------------------------------------------------------------------
    | JWT hashing algorithm
    |--------------------------------------------------------------------------
    |
    | Specify the hashing algorithm that will be used to sign the token.
    |
    | See here: https://github.com/namshi/jose/tree/2.2.0/src/Namshi/JOSE/Signer
    | for possible values
    |
    */

    'algo' => 'HS256',

    /*
    |--------------------------------------------------------------------------
    | User Model namespace
    |--------------------------------------------------------------------------
    |
    | Specify the full namespace to your User model.
    | e.g. 'Acme\Entities\User'
    |
    */

    'user' => 'App\User',

    /*
    |--------------------------------------------------------------------------
    | User identifier
    |--------------------------------------------------------------------------
    |
    | Specify a unique property of the user that will be added as the 'sub'
    | claim of the token payload.
    |
    */

    'identifier' => 'id',

    /*
    |--------------------------------------------------------------------------
    | Required Claims
    |--------------------------------------------------------------------------
    |
    | Specify the required claims that must exist in any token.
    | A TokenInvalidException will be thrown if any of these claims are not
    | present in the payload.
    |
    */

    'required_claims' => ['iss', 'iat', 'exp', 'nbf', 'sub', 'jti'],

    /*
    |--------------------------------------------------------------------------
    | Blacklist Enabled
    |--------------------------------------------------------------------------
    |
    | In order to invalidate tokens, you must have the the blacklist enabled.
    | If you do not want or need this functionality, then set this to false.
    |
    */

    'blacklist_enabled' => env('JWT_BLACKLIST_ENABLED', true),

    /*
    | -------------------------------------------------------------------------
    | Blacklist Delay Time
    | -------------------------------------------------------------------------
    |
    | When multiple concurrent requests are made to the api endpoints with
    | same JWT, It is possible that some of them fail, due to token regeneration
    | on every request.
    |
    | Set delay time in seconds to prevent the parallel request failure.
    |
    */
    'blacklist_delay' => env('JWT_BLACKLIST_DELAY', 0),

    /*
    |--------------------------------------------------------------------------
    | Providers
    |--------------------------------------------------------------------------
    |
    | Specify the various providers used throughout the package.
    |
    */

    'providers' => [

        /*
        |--------------------------------------------------------------------------
        | User Provider
        |--------------------------------------------------------------------------
        |
        | Specify the provider that is used to find the user based
        | on the subject claim
        |
        */

        'user' => 'Tymon\JWTAuth\Providers\User\EloquentUserAdapter',

        /*
        |--------------------------------------------------------------------------
        | JWT Provider
        |--------------------------------------------------------------------------
        |
        | Specify the provider that is used to create and decode the tokens.
        |
        */

        'jwt' => 'Tymon\JWTAuth\Providers\JWT\NamshiAdapter',

        /*
        |--------------------------------------------------------------------------
        | Authentication Provider
        |--------------------------------------------------------------------------
        |
        | Specify the provider that is used to authenticate users.
        |
        */

        'auth' => function ($app) {
            return new Tymon\JWTAuth\Providers\Auth\IlluminateAuthAdapter($app['auth']);
        },

        /*
        |--------------------------------------------------------------------------
        | Storage Provider
        |--------------------------------------------------------------------------
        |
        | Specify the provider that is used to store tokens in the blacklist
        |
        */

        'storage' => function ($app) {
            return new Tymon\JWTAuth\Providers\Storage\IlluminateCacheAdapter($app['cache']);
        }

    ]

];
