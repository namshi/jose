<?php

namespace Namshi\JOSE\Signer\OpenSSL;

use InvalidArgumentException;
use Namshi\JOSE\Signer\SignerInterface;
use RuntimeException;

/**
 * Class responsible to sign inputs with the a public key algorithm, after hashing it.
 */
abstract class PublicKey implements SignerInterface
{
    /**
     * {@inheritdoc}
     */
    public function sign($input, $key, $password = null)
    {
        $keyResource = $this->getKeyResource($key, $password);
        if (!$this->supportsKey($keyResource)) {
            throw new InvalidArgumentException('Invalid key supplied.');
        }

        $signature = null;
        openssl_sign($input, $signature, $keyResource, $this->getHashingAlgorithm());

        return $signature;
    }

    /**
     * {@inheritdoc}
     */
    public function verify($key, $signature, $input)
    {
        $keyResource = $this->getKeyResource($key);
        if (!$this->supportsKey($keyResource)) {
            throw new InvalidArgumentException('Invalid key supplied.');
        }

        $result = openssl_verify($input, $signature, $keyResource, $this->getHashingAlgorithm());

        if ($result === -1) {
            throw new RuntimeException('Unknown error during verification.');
        }

        return (bool) $result;
    }

    /**
     * Converts a string representation of a key into an OpenSSL resource.
     *
     * @param string|resource $key
     * @param string          $password
     *
     * @return resource OpenSSL key resource
     */
    protected function getKeyResource($key, $password = null)
    {
        if (is_resource($key)) {
            return $key;
        }

        $resource = openssl_pkey_get_public($key) ?: openssl_pkey_get_private($key, $password);
        if ($resource === false) {
            throw new RuntimeException('Could not read key resource: ' . openssl_error_string());
        }
        return $resource;
    }

    /**
     * Check if the key is supported by this signer.
     *
     * @param resource $key Public or private key
     *
     * @return bool
     */
    protected function supportsKey($key)
    {
        // OpenSSL 0.9.8+
        $keyDetails = openssl_pkey_get_details($key);

        return isset($keyDetails['type']) ? $this->getSupportedPrivateKeyType() === $keyDetails['type'] : false;
    }

    /**
     * Returns the hashing algorithm used in this signer.
     *
     * @return string
     */
    abstract protected function getHashingAlgorithm();

    /**
     * Returns the private key type supported in this signer.
     *
     * @return string
     */
    abstract protected function getSupportedPrivateKeyType();
}
