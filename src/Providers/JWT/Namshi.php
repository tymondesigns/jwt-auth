<?php declare(strict_types=1);

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Providers\JWT;

use InvalidArgumentException;
use Namshi\JOSE\JWS;
use Namshi\JOSE\Signer\OpenSSL\PublicKey;
use ReflectionClass;
use ReflectionException;
use Throwable;
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
     * @param  string|null|object  $driver
     */
    public function __construct(string $secret, string $algo, array $keys = [], $driver = null)
    {
        parent::__construct($secret, $keys, $algo);

        $this->jws = $driver ?: new JWS(['typ' => 'JWT', 'alg' => $algo]);
    }

    /**
     * Create a JSON Web Token.
     *
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function encode(array $payload): string
    {
        try {
            $this->jws->setPayload($payload)->sign($this->getSigningKey(), $this->getPassphrase());

            return (string) $this->jws->getTokenString();
        } catch (Throwable $e) {
            throw new JWTException('Could not create token: '.$e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Decode a JSON Web Token.
     *
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function decode(string $token): array
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
     * Determine if the algorithm is asymmetric, and thus
     * requires a public/private key combo.
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    protected function isAsymmetric(): bool
    {
        try {
            return (new ReflectionClass(sprintf('Namshi\\JOSE\\Signer\\OpenSSL\\%s', $this->getAlgo())))->isSubclassOf(PublicKey::class);
        } catch (ReflectionException $e) {
            throw new JWTException('The given algorithm could not be found', $e->getCode(), $e);
        }
    }

    /**
     * Get the key used to sign the tokens.
     *
     * @return resource|string
     */
    protected function getSigningKey()
    {
        return $this->isAsymmetric() ? $this->getPrivateKey() : $this->getSecret();
    }

    /**
     * Get the key used to verify the tokens.
     *
     * @return resource|string
     */
    protected function getVerificationKey()
    {
        return $this->isAsymmetric() ? $this->getPublicKey() : $this->getSecret();
    }
}
