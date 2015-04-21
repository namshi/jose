<?php

namespace Namshi\JOSE\Signer\OpenSSL;

/**
 * HMAC Signer using SHA-256.
 */
class HS256 extends HMAC
{
    public function getHashingAlgorithm()
    {
        return 'sha256';
    }
}
