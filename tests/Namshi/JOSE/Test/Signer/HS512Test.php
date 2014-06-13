<?php

namespace Namshi\JOSE\Test\Signer;

use \PHPUnit_Framework_TestCase as TestCase;
use Namshi\JOSE\Signer\HS512;

class HS512Test extends TestCase
{
    public function testSigningAndVerificationWorkProperly()
    {
        $signer = new HS512;
        $signature = $signer->sign('aaa', 'foo');

        $this->assertEquals($signature, '1b2b2a457f06a03e81093ac8e6c272d69b67f40eef6c396f14e9da0313bfb7e043f0a56b54051570733180cebc64dc6750d91bee4352ab7631902578a41bd38e');

        $this->assertTrue($signer->verify('foo', $signature, 'aaa'));
        $this->assertFalse($signer->verify('bar', $signature, 'aaa'));
    }
}
