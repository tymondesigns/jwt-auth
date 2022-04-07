<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Providers\JWT;

use Exception;
use InvalidArgumentException;
use Namshi\JOSE\JWS;
use Namshi\JOSE\Signer\OpenSSL\PublicKey;
use ReflectionClass;
use ReflectionException;
use Tymon\JWTAuth\Contracts\Providers\JWT;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class Namshi extends Provider implements JWT
{
    /**
     * The JWS.
     *
     * @var \Namshi\JOSE\JWS
     */
    protected $jws;

    /**
     * Constructor.
     *
     * @param  \Namshi\JOSE\JWS  $jws
     * @param  string  $secret
     * @param  string  $algo
     * @param  array  $keys
     * @return void
     */
    public function __construct(JWS $jws, $secret, $algo, array $keys)
    {
        parent::__construct($secret, $algo, $keys);

        $this->jws = $jws;
    }

    /**
     * Create a JSON Web Token.
     *
     * @param  array  $payload
     * @return string
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function encode(array $payload)
    {
        try {
            $this->jws->setPayload($payload)->sign($this->getSigningKey(), $this->getPassphrase());

            return (string) $this->jws->getTokenString();
        } catch (Exception $e) {
            throw new JWTException('Could not create token: '.$e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Decode a JSON Web Token.
     *
     * @param  string  $token
     * @return array
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function decode($token)
    {
        try {
            // Let's never allow insecure tokens
            $jws = $this->jws->load($token, false);
        } catch (InvalidArgumentException $e) {
            throw new TokenInvalidException('Could not decode token: '.$e->getMessage(), $e->getCode(), $e);
        }

        if (! $jws->verify($this->getVerificationKey(), $this->getAlgo())) {
            throw new TokenInvalidException('Token Signature could not be verified.');
        }

        return (array) $jws->getPayload();
    }

    /**
     * {@inheritdoc}
     */
    protected function isAsymmetric()
    {
        try {
            return (new ReflectionClass(sprintf('Namshi\\JOSE\\Signer\\OpenSSL\\%s', $this->getAlgo())))->isSubclassOf(PublicKey::class);
        } catch (ReflectionException $e) {
            throw new JWTException('The given algorithm could not be found', $e->getCode(), $e);
        }
    }
}
