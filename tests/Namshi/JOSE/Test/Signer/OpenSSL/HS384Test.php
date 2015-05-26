<?php

namespace Namshi\JOSE\Test\OpenSSL\Signer;

use \PHPUnit_Framework_TestCase as TestCase;
use Namshi\JOSE\Signer\OpenSSL\HS384;

class HS384Test extends TestCase
{
    public function testSigningAndVerificationWorkProperly()
    {
        $signer = new HS384;
        $signature = $signer->sign('aaa', 'foo');

        $this->assertEquals($signature, base64_decode('W6Cd7qZknNYIXOxTrpEWFFwfuX0e2j59hTH4kVFh5o+9rcnfNtphLg4V8YXfkXGF'));

        $this->assertTrue($signer->verify('foo', $signature, 'aaa'));
        $this->assertFalse($signer->verify('bar', $signature, 'aaa'));
    }
}
