<?php

namespace Namshi\JOSE\Test\OpenSSL\Signer;

use Namshi\JOSE\Signer\OpenSSL\ES384;
use Namshi\JOSE\Test\Signer\SecLib\SecLibTestCase;

class ES384Test extends SecLibTestCase
{
    public function setup()
    {
        parent::setup();
        // https://github.com/sebastianbergmann/phpunit/issues/1356
        if (defined('HHVM_VERSION')) {
            $this->markTestSkipped();
        }
        $this->privateKey = openssl_pkey_get_private(SSL_KEYS_PATH.'private.es384.key', 'tests');
        $this->public = openssl_pkey_get_public(SSL_KEYS_PATH.'public.es384.key');
        $this->signer = new ES384();
        $this->teststring=openssl_random_pseudo_bytes(64);
    }

    public function testVerificationWorksProperly()
    {
        $encrypted = $this->signer->sign($this->teststring, $this->privateKey);
        $this->assertInternalType('bool', $this->signer->verify($this->public, $encrypted, $this->teststring));
        $this->assertTrue($this->signer->verify($this->public, $encrypted, $this->teststring));
    }

    public function testModifiedPayloadVerificationFails()
    {
        $encrypted = $this->signer->sign($this->teststring, $this->privateKey);
        $this->assertInternalType('bool', $this->signer->verify($this->public, $encrypted, $this->teststring));
        $this->assertTrue($this->signer->verify($this->public, $encrypted, $this->teststring));
        
        $testStringModified=$this->teststring;
        
        $positionInPayload=mt_rand(0,strlen($this->teststring)-1);
        do{
            $testStringModified[$positionInPayload]=openssl_random_pseudo_bytes(1);
        }while($testStringModified[$positionInPayload] == $this->teststring[$positionInPayload]);
        
        $this->assertFalse($this->signer->verify($this->public, $encrypted, $testStringModified));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid key supplied.
     */
    public function testWrongKeyCurve()
    {
        $privateKey512 = openssl_pkey_get_private(SSL_KEYS_PATH.'private.es512.key');
        $this->signer->sign('aaa', $privateKey512);
    }

    public function testSigningWorksProperly()
    {
        $this->assertInternalType('string', $this->signer->sign('aaa', $this->privateKey));
    }
}
