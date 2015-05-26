<?php

namespace Namshi\JOSE\Test\OpenSSL\Signer;

use \PHPUnit_Framework_TestCase as TestCase;
use Namshi\JOSE\Signer\OpenSSL\HS512;

class HS512Test extends TestCase
{
    public function testSigningAndVerificationWorkProperly()
    {
        $signer = new HS512;
        $signature = $signer->sign('aaa', 'foo');

        $this->assertEquals($signature, base64_decode('GysqRX8GoD6BCTrI5sJy1ptn9A7vbDlvFOnaAxO/t+BD8KVrVAUVcHMxgM68ZNxnUNkb7kNSq3YxkCV4pBvTjg=='));

        $this->assertTrue($signer->verify('foo', $signature, 'aaa'));
        $this->assertFalse($signer->verify('bar', $signature, 'aaa'));
    }
}
