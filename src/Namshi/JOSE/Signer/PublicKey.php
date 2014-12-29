<?php

namespace Namshi\JOSE\Signer;

use InvalidArgumentException;

/**
 * Class responsible to sign inputs with the a public key algorithm, after hashing it.
 */
abstract class PublicKey implements SignerInterface
{

    /**
     * @inheritdoc
     */
    public function sign($input, $key)
    {
        if (!$this->supportsKey($key)) {
            throw new InvalidArgumentException('Invalid key supplied.');
        }

        $signature = null;
        openssl_sign($input, $signature, $key, $this->getHashingAlgorithm());

        return $signature;
    }

    /**
     * @inheritdoc
     */
    public function verify($key, $signature, $input)
    {
        if (!$this->supportsKey($key)) {
            throw new InvalidArgumentException('Invalid key supplied.');
        }

        return (bool) openssl_verify($input, $signature, $key, $this->getHashingAlgorithm());
    }

    /**
     * Check if the key is supported by this signer.
     *
     * @param  resource $key Public or private key
     * @return boolean
     */
    protected function supportsKey($key)
    {
        if (!is_resource($key)) {
            $key = openssl_pkey_get_public($key) ?: openssl_pkey_get_private($key);
            if (!$key) {
               return false;
            }
        }
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
