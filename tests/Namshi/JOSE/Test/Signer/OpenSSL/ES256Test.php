<?php

namespace Namshi\JOSE\Test\OpenSSL\Signer;

use Namshi\JOSE\Signer\OpenSSL\ES256;
use Namshi\JOSE\Test\Signer\SecLib\SecLibTestCase;

class ES256Test extends SecLibTestCase
{
    public function setup()
    {
        parent::setup();
        // https://github.com/sebastianbergmann/phpunit/issues/1356
        if (defined('HHVM_VERSION')) {
            $this->markTestSkipped();
        }
        $this->privateKey = openssl_pkey_get_private(SSL_KEYS_PATH.'private.es256.key');
        $this->public = openssl_pkey_get_public(SSL_KEYS_PATH.'public.es256.key');
        $this->signer = new ES256();
    }

    public function testVerificationWorksProperly()
    {
        $encrypted = $this->signer->sign('aaa', $this->privateKey);
        $this->assertInternalType('bool', $this->signer->verify($this->public, $encrypted, 'aaa'));
        $this->assertTrue($this->signer->verify($this->public, $encrypted, 'aaa'));
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
