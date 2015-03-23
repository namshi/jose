<?php

namespace Namshi\JOSE\Test\SecLib\Signer;

use Namshi\JOSE\Signer\SecLib\RS256;
use \PHPUnit_Framework_TestCase as TestCase;

class RS256Test extends TestCase {
    public function setup()
    {
        $this->privateKey   = file_get_contents(SSL_KEYS_PATH . "private.key");
        $this->public       = file_get_contents(SSL_KEYS_PATH . "public.key");
        $this->password     = 'tests';
        $this->signer       = new RS256();
    }

    public function testVerificationWorksProperly()
    {
        $encrypted = $this->signer->sign('aaa', $this->privateKey, $this->password);
        $this->assertInternalType('bool', $this->signer->verify($this->public, $encrypted, 'aaa'));
        $this->assertTrue($this->signer->verify($this->public, $encrypted, 'aaa'));
    }

    public function testSigningWorksProperly()
    {
        $this->assertInternalType('string', $this->signer->sign('aaa', $this->privateKey, $this->password));
    }

}
