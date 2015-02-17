<?php

namespace Tymon\JWTAuth\Middleware;

use Tymon\JWTAuth\JWTAuth;
use Illuminate\Events\Dispatcher;
use Illuminate\Routing\ResponseFactory;

abstract class BaseMiddleware
{
    /**
     * @var \Illuminate\Routing\ResponseFactory
     */
    protected $response;

    /**
     * @var \Illuminate\Events\Dispatcher
     */
    protected $events;

    /**
     * @var \Tymon\JWTAuth\JWTAuth
     */
    protected $auth;

    /**
     * Create a new BaseMiddleware instance
     *
     * @param \Illuminate\Routing\ResponseFactory  $response
     * @param \Illuminate\Events\Dispatcher  $events
     * @param \Tymon\JWTAuth\JWTAuth  $auth
     */
    public function __construct(ResponseFactory $response, Dispatcher $events, JWTAuth $auth)
    {
        $this->response = $response;
        $this->events = $events;
        $this->auth = $auth;
    }

    /**
     * Fire event and return the response
     *
     * @param  string   $event
     * @param  string   $error
     * @param  integer  $status
     * @param  array    $payload
     * @return mixed
     */
    protected function respond($event, $error, $status, $payload = [])
    {
        $response = $this->events->fire($event, $payload, true);

        return $response ?: $this->response->json(['error' => $error], $status);
    }
}
