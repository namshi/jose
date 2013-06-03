<?php

namespace Namshi\JOSE\Signer;

use Namshi\JOSE\Signer\SignerInterface;

/**
 * Class responsible to sign inputs with the RSA algorithm, after hashing it.
 */
class RS256 implements SignerInterface
{
    const HASH_ALGORITHM = "SHA256";
    
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
        return pack('H*', '3031300d060960864801650304020105000420') . hash(self::HASH_ALGORITHM, $input, true);
    }
}
