<?php

namespace Namshi\JOSE\Test\OpenSSL\Signer;

use Namshi\JOSE\Signer\OpenSSL\ES384;
use \PHPUnit_Framework_TestCase as TestCase;

class ES384Test extends TestCase
{

    public function setup()
    {
        // https://github.com/sebastianbergmann/phpunit/issues/1356
        if (defined('HHVM_VERSION')) {
            $this->markTestSkipped();
        }
        $this->privateKey = openssl_pkey_get_private(SSL_KEYS_PATH . "private.es384.key", 'tests');
        $this->public = openssl_pkey_get_public(SSL_KEYS_PATH . "public.es384.key");
        $this->signer = new ES384;
    }

    public function testVerificationWorksProperly()
    {
        $encrypted = $this->signer->sign('aaa', $this->privateKey);
        $this->assertInternalType('bool', $this->signer->verify($this->public, $encrypted, 'aaa'));
        $this->assertTrue($this->signer->verify($this->public, $encrypted, 'aaa'));
    }

    public function testSigningWorksProperly()
    {
        $this->assertInternalType('string', $this->signer->sign('aaa', $this->privateKey));
    }

}
