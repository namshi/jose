<?php

namespace Namshi\JOSE\Signer;

/**
 * Class responsible to sign inputs with the RSA algorithm, after hashing it.
 */
abstract class RSA implements SignerInterface
{
    /**
     * @inheritdoc
     */
    public function sign($input, $key)
    {
        $signature = null;
        openssl_sign($input, $signature, $key, $this->getHashingAlgorithm());

        return $signature;
    }

    /**
     * @inheritdoc
     */
    public function verify($key, $signature, $input)
    {
        return (bool) openssl_verify($input, $signature, $key, $this->getHashingAlgorithm());
    }

    /**
     * Returns the hashing algorithm used in this signer.
     *
     * @return string
     */
    abstract public function getHashingAlgorithm();
}
