<?php

namespace Tymon\JWTAuth\Validators;

interface ValidatorInterface
{
	public static function check($value);
}