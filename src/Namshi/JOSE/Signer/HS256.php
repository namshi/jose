<?php

namespace Namshi\JOSE\Signer;

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
