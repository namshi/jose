<?php


namespace Namshi\JOSE\Signer\SecLib;


class RS384 extends RSA
{
    public function __construct() {
        parent::__construct();
        $this->encryptionAlgorithm->setHash('sha384');
        $this->encryptionAlgorithm->setMGFHash('sha384');
    }
}
