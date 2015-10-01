<?php

namespace Namshi\JOSE\Signer\OpenSSL;

/**
 * HMAC Signer using SHA-384.
 */
class HS384 extends HMAC
{
    /**
     * {@inheritdoc}
     */
    public function getHashingAlgorithm()
    {
        return 'sha384';
    }
}
