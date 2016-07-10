<?php

namespace Namshi\JOSE;

/**
 * Class providing an easy to use JWS implementation.
 */
class SimpleJWS extends JWS
{
    /**
     * Constructor.
     *
     * @param array $header An associative array of headers. The value can be any type accepted by json_encode or a JSON serializable object
     *
     * @see http://php.net/manual/en/function.json-encode.php
     * @see http://php.net/manual/en/jsonserializable.jsonserialize.php
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4
     * }
     */
    public function __construct($header = array(), $encryptionEngine = 'OpenSSL')
    {
        if (!isset($header['typ'])) {
            $header['typ'] = 'JWS';
        }
        parent::__construct($header, $encryptionEngine);
    }

    /**
     * Sets the payload of the current JWS with an issued at value in the 'iat' property.
     *
     * @param array $payload
     *
     * @return $this
     */
    public function setPayload(array $payload)
    {
        if (!isset($payload['iat'])) {
            $payload['iat'] = time();
        }

        return parent::setPayload($payload);
    }

    /**
     * Checks that the JWS has been signed with a valid private key by verifying it with a public $key
     * and the token is not expired.
     *
     * @param resource|string $key
     * @param string          $algo The algorithms this JWS should be signed with. Use it if you want to restrict which algorithms you want to allow to be validated.
     *
     * @return bool
     */
    public function isValid($key, $algo = null)
    {
        return $this->verify($key, $algo) && !$this->isExpired();
    }

    /**
     * Checks whether the token is expired based on the 'exp' value.
     *it.
     *
     * @return bool
     */
    public function isExpired()
    {
        $payload = $this->getPayload();

        if (isset($payload['exp'])) {
            $now = new \DateTime('now');

            if (is_int($payload['exp'])) {
                return ($now->getTimestamp() - $payload['exp']) > 0;
            }

            if (is_numeric($payload['exp'])) {
                return ($now->format('U') - $payload['exp']) > 0;
            }
        }

        return false;
    }
}
