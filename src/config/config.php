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
	|
	*/

	'ttl' => 120,

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
