<?php namespace Tymon\JWTAuth\Storage;

interface Storable
{
	public function add($token);

	public function get($id);

	public function exists($token);

	public function destroy($token);
}