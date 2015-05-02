<?php

namespace Tymon\JWTAuth;

interface JWTAuthSubject
{
    public function getIdentifier();
}