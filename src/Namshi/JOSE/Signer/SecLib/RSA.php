<?php


namespace Namshi\JOSE\Signer\SecLib;


class RSA extends PublicKey
{
    public function __construct() {
        $this->encryptionAlgorithm = new \Crypt_RSA();
    }
}
