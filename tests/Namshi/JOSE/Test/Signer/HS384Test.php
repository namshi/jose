<?php

namespace Namshi\JOSE\Test\Signer;

use \PHPUnit_Framework_TestCase as TestCase;
use Namshi\JOSE\Signer\HS384;

class HS384Test extends TestCase
{
    public function testSigningAndVerificationWorkProperly()
    {
        $signer = new HS384;
        $signature = $signer->sign('aaa', 'foo');

        $this->assertEquals($signature, '5ba09deea6649cd6085cec53ae9116145c1fb97d1eda3e7d8531f8915161e68fbdadc9df36da612e0e15f185df917185');

        $this->assertTrue($signer->verify('foo', $signature, 'aaa'));
        $this->assertFalse($signer->verify('bar', $signature, 'aaa'));
    }
}
