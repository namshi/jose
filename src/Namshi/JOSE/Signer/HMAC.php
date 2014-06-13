<?php

namespace Namshi\JOSE\Signer;

/**
 * This class is the base of all HMAC Signers
 */
abstract class HMAC implements SignerInterface
{
    /**
     * @inheritdoc
     */
    public function sign($input, $key)
    {
        return hash_hmac($this->getHashingAlgorithm(), $input, $key);
    }

    /**
     * @inheritdoc
     */
    public function verify($key, $signature, $input)
    {
        return $signature === $this->sign($input, $key);
    }

    /**
     * Returns the hashing algorithm used in this signer.
     *
     * @return string
     */
    abstract public function getHashingAlgorithm();
}
