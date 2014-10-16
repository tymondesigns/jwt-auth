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
	| Defaults to 24 hours
	|
	*/

	'ttl' => 1440,

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
	| Your User must extend Eloquent (Illuminate\Database\Eloquent\Model)
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
	| JWT Provider
	|--------------------------------------------------------------------------
	| 
	| Specify the JWT provider to do the heavy lifting of encoding, signing
	| and decoding JSON Web Tokens 
	|
	*/

	'provider' => 'Tymon\JWTAuth\Providers\FirebaseProvider'

];
