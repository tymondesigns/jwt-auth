<?php

return [

    /*
    |--------------------------------------------------------------------------
    | JWT Authentication Secret
    |--------------------------------------------------------------------------
    |
    | Don't forget to set this, as it will be used to sign your tokens.
    |
    */

    'secret' => 'changeme',

    /*
    |--------------------------------------------------------------------------
    | JWT time to live
    |--------------------------------------------------------------------------
    |
    | Specify the length of time (in minutes) that the token will be valid for.
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
    | within. E.g. The user can refresh their token within a 2 week window of
    | the original token being created until they must re-authenticate.
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
    | Possible values are:
    | 'HS256', 'HS512', 'HS384', 'RS256'
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

    'user' => 'User',

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

        'jwt' => 'Tymon\JWTAuth\Providers\JWT\FirebaseAdapter',

        /*
        |--------------------------------------------------------------------------
        | Authentication Provider
        |--------------------------------------------------------------------------
        |
        | Specify the provider that is used to authenticate users.
        |
        */

        'auth' => 'Tymon\JWTAuth\Providers\Auth\IlluminateAuthAdapter',

        /*
        |--------------------------------------------------------------------------
        | Storage Provider
        |--------------------------------------------------------------------------
        |
        | Specify the provider that is used to store the tokens in a 'registry'
        |
        */

        'storage' => 'Tymon\JWTAuth\Providers\Storage\IlluminateCacheAdapter'

    ]

];
