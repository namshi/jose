<?php

namespace Namshi\JOSE\Test\Signer;

use \PHPUnit_Framework_TestCase as TestCase;
use Namshi\JOSE\Signer\HS256;

class HS256Test extends TestCase
{
    public function testSigningAndVerificationWorkProperly()
    {
        $signer = new HS256;
        $signature = $signer->sign('aaa', 'foo');

        $this->assertEquals($signature, '3f63dbf1ed896b83f86274d9dc4174d3644aa54a4e9df8c8cb4b8b353d11d49d');

        $this->assertTrue($signer->verify('foo', $signature, 'aaa'));
        $this->assertFalse($signer->verify('bar', $signature, 'aaa'));
    }
}
