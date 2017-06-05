<?php

/*
* This file is part of jwt-auth.
*
* (c) Sean Tymon <tymon148@gmail.com>
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*/

namespace Tymon\JWTAuth\Providers\Auth;

use Tymon\JWTAuth\Contracts\Providers\Auth;
use LaravelDoctrine\ORM\Auth\DoctrineUserProvider;

/**
 * Class Doctrine.
 *
 * @package Tymon\JWTAuth\Providers\Auth
 * @author James Kirkby <me@jameskirkby.com>
 */
class Doctrine implements Auth
{

    /**
     * @var DoctrineUserProvider
     */
    protected $doctrineUserAdapter;

    /**
     * @var
     */
    protected $user;

    /**
     * DoctrineUserAdapter constructor.
     *
     * @param DoctrineUserProvider $doctrineUserProvider
     */
    public function __construct(DoctrineUserProvider $doctrineUserProvider)
    {
        $this->doctrineUserAdapter = $doctrineUserProvider;
    }

    /**
     * @param array $credentials
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function byCredentials(array $credentials)
    {
        $this->user = $this->doctrineUserAdapter->retrieveByCredentials($credentials);
        return $this->user;
    }

    /**
     * @param mixed $id
     * 
     * @return mixed
     */
    public function byId($id)
    {
        $this->user = $this->doctrineUserAdapter->retrieveById($id);
        
        return $this->user;
    }

    /**
     * @return mixed
     */
    public function user()
    {
        return $this->user;
    }
}
