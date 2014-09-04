<?php

return [

	/*
	|--------------------------------------------------------------------------
	| JWT Authentication Secret
	|--------------------------------------------------------------------------
	| 
	| Don't forget to set this, as it will be used to sign your token.
	|
	*/

	'secret' => 'fq344c4ftgfvw34ft435g6w45tf34ft',

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

	'identifier' => 'id'

];