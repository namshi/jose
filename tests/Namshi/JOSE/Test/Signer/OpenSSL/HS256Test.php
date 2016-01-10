<?php

namespace Namshi\JOSE\Test\OpenSSL\Signer;

use Namshi\JOSE\Signer\OpenSSL\HS256;
use PHPUnit_Framework_TestCase as TestCase;

class HS256Test extends TestCase
{
    public function testSigningAndVerificationWorkProperly()
    {
        $signer = new HS256();
        $signature = $signer->sign('aaa', 'foo');
        $this->assertEquals($signature, base64_decode('P2Pb8e2Ja4P4YnTZ3EF002RKpUpOnfjIy0uLNT0R1J0='));

        $this->assertTrue($signer->verify('foo', $signature, 'aaa'));
        $this->assertFalse($signer->verify('bar', $signature, 'aaa'));
    }
}
