<?php

namespace Namshi\JOSE\Signer;

/**
 * HMAC Signer using SHA-384.
 */
class HS384 extends HMAC
{
    public function getHashingAlgorithm()
    {
        return 'sha384';
    }
}
