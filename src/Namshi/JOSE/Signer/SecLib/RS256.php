<?php

namespace Namshi\JOSE\Signer\SecLib;

class RS256 extends RSA
{
    /**
     * {@inheritdoc}
     */
    protected function configureEncryptionAlgorithm(\Crypt_RSA $encryptionAlgorithm)
    {
        $encryptionAlgorithm->setHash('sha256');
        $encryptionAlgorithm->setMGFHash('sha256');
    }
}
