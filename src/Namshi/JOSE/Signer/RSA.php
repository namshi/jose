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
        $cipherText = null;
        
        if(openssl_private_encrypt($this->hash($input), $cipherText, $key))
        {
            return $cipherText;
        }
        
        return null;
    }
    
    /**
     * @inheritdoc
     */
    public function verify($key, $signature, $input)
    {
        $plainText  = NULL;
        
        if(openssl_public_decrypt($signature, $plainText, $key)) {
            return $plainText === $this->hash($input);
        }
        
        return false;
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
