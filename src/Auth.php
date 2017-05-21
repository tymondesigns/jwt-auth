<?php namespace Tymon\JWTAuth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;
use Koodzo\Models\Db\User;
use Tymon\JWTAuth\JWTAuth;

class Auth implements Guard
{
    protected $auth;

    public function __construct(JWTAuth $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Determine if the current user is authenticated.
     *
     * @return bool
     */
    public function check()
    {
        try
        {
            return ($token = $this->auth->parseToken()) && ($user = $this->auth->authenticate($token->getToken()));
        }
        catch (\Exception $e)
        {
            return false;
        }
    }

    /**
     * Determine if the current user is a guest.
     *
     * @return bool
     */
    public function guest()
    {
        return !$this->check();
    }

    /**
     * Get the currently authenticated user's ID.
     *
     * @return int|null
     */
    public function id()
    {
        return $this->auth->parseToken()->getPayload()->get('sub');
    }

    /**
     * Get the currently authenticated user.
     *
     * @param array $attr Attributes to retrieve.
     *
     * @return \Koodzo\Models\Db\User|null
     */
    public function user($attr = ['*'])
    {
        $id = $this->auth->parseToken()->getPayload()->get('sub');

        return User::whereId($id)->first($attr);
    }

    /**
     * Log a user into the application without sessions or cookies.
     *
     * @param  array $credentials
     * @return bool
     */
    public function once(array $credentials = [])
    {
        // Skip
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param  array $credentials
     * @param  bool $remember
     * @param  bool $login
     * @return false|string
     */
    public function attempt(array $credentials = [], $remember = false, $login = true)
    {
        return $this->auth->attempt($credentials);
    }

    /**
     * Attempt to authenticate using HTTP Basic Auth.
     *
     * @param  string $field
     * @return \Symfony\Component\HttpFoundation\Response|null
     */
    public function basic($field = 'email')
    {
        // Skip
    }

    /**
     * Perform a stateless HTTP Basic login attempt.
     *
     * @param  string $field
     * @return \Symfony\Component\HttpFoundation\Response|null
     */
    public function onceBasic($field = 'email')
    {
        // Skip
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array $credentials
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        return !!$this->auth->attempt($credentials);
    }

    /**
     * Log a user into the application.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable $user
     * @param  bool $remember
     * @return string
     */
    public function login(Authenticatable $user, $remember = false)
    {
        return $this->auth->fromUser($user);
    }

    /**
     * Log the given user ID into the application.
     *
     * @param  mixed $id
     * @param  bool $remember
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    public function loginUsingId($id, $remember = false)
    {
        $user = User::whereId($id)->first();

        return $this->auth->fromUser($user);
    }

    /**
     * Determine if the user was authenticated via "remember me" cookie.
     *
     * @return bool
     */
    public function viaRemember()
    {
        // Skip
    }

    /**
     * Log the user out of the application.
     *
     * @return void
     */
    public function logout()
    {
        $this->auth->invalidate($this->auth->getToken());
    }
}
