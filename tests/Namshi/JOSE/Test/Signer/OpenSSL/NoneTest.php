<?php

namespace Namshi\JOSE\Test\OpenSSL\Signer;

use Namshi\JOSE\Signer\OpenSSL\None;
use PHPUnit_Framework_TestCase as TestCase;

class NoneTest extends TestCase
{
    public function testVerificationWorksProperly()
    {
        $signer = new none();

        $this->assertTrue($signer->verify('bar', '', 'aaa'));
    }

    public function testSigningWorksProperly()
    {
        $signer = new none();
        $signature = $signer->sign('aaa', 'foo');

        $this->assertTrue($signature === '');
    }
}
