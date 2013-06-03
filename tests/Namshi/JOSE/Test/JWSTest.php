<?php

namespace Namshi\JOSE\Test;

use PHPUnit_Framework_TestCase as TestCase;
use Namshi\JOSE\JWS;

class JWSTest extends TestCase
{
    const SSL_KEY_PASSPHRASE = 'tests';
    
    public function setup()
    {
        $data       = array('a' => 'b');
        $this->jws  = new JWS('RS256');
        $this->jws->setPayload($data);
    }
    
    public function getSslKeyPath()
    {
        return "file://" . TEST_DIR . DIRECTORY_SEPARATOR;
    }
    
    public function testVerificationRS256()
    {
        $privateKey = openssl_pkey_get_private($this->getSslKeyPath() . "private.key", self::SSL_KEY_PASSPHRASE);
        $this->jws->sign($privateKey);
        
        $jws        = JWS::load($this->jws->getTokenString());
        $public_key = openssl_pkey_get_public($this->getSslKeyPath() . "public.key");
        $this->assertTrue($jws->verify($public_key));
        
        $payload = $jws->getPayload();
        $this->assertEquals('b', $payload['a']);
    }
    
    public function testVerificationThatTheJWSIsSigned()
    {
        $privateKey = openssl_pkey_get_private($this->getSslKeyPath() . "private.key", self::SSL_KEY_PASSPHRASE);
        $this->jws->sign($privateKey);
        $this->assertTrue($this->jws->isSigned());
    }
    
    public function testVerificationThatTheJWSIsNotSigned()
    {
        $this->assertFalse($this->jws->isSigned());
    }
    
    /**
     * @expectedException InvalidArgumentException
     */
    public function testWrongVerificationRS256()
    {
        $privateKey = openssl_pkey_get_private($this->getSslKeyPath() . "private.key", self::SSL_KEY_PASSPHRASE);
        $this->jws->sign($privateKey);
        
        $jws        = JWS::load('eyJhbGciOiJ0ZXN0In0=.eyJhbGciOiJ0ZXN0In0=.eyJhbGciOiJ0ZXN0In0=', true);
        $public_key = openssl_pkey_get_public($this->getSslKeyPath() . "public.key");
        $this->assertFalse($jws->verify($public_key));
    }
    
    /**
     * @expectedException InvalidArgumentException
     */
    public function testLoadingAMalformedTokenString()
    {
        JWS::load('test.Test.TEST', true);
    }
    
    /**
     * @expectedException InvalidArgumentException
     */
    public function testLoadingAMalformedTokenString2()
    {
        JWS::load('test', true);
    }
}