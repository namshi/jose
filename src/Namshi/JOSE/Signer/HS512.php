<?php

namespace Namshi\JOSE\Signer;

/**
 * HMAC Signer using SHA-512.
 */
class HS512 extends HMAC
{
    public function getHashingAlgorithm()
    {
        return 'sha512';
    }
}
