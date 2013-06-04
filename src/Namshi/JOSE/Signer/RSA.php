<?php

namespace Namshi\JOSE\Signer;

use Namshi\JOSE\Signer\SignerInterface;

/**
 * Class responsible to sign inputs with the RSA algorithm, after hashing it.
 */
abstract class RSA implements SignerInterface
{
    protected $hashingAlgorithm = null;
    
    /**
     * @inheritdoc
     */
    public function sign($input, $key)
    {
        $signature = null;
        openssl_sign($input, $signature, $key, $this->hashingAlgorithm);
        
        return $signature;
    }
    
    /**
     * @inheritdoc
     */
    public function verify($key, $signature, $input)
    {
        return (bool) openssl_verify($input, $signature, $key, $this->hashingAlgorithm);
    }
    
    /**
     * Hashes the $input.
     * 
     * @param type $input
     * @return string
     */
    protected function hash($input)
    {
        return hash($this->getHashingAlgorithm(), $input, true);
    }
    
    /**
     * Returns the hashing algorithm used in this signer.
     * 
     * @return string
     */
    public function getHashingAlgorithm()
    {
        return $this->hashingAlgorithm;
    }
}
