<?php

namespace Namshi\JOSE\Test;

use PHPUnit_Framework_TestCase as TestCase;
use Namshi\JOSE\Base64;

class Base64Test extends TestCase
{
    public function testEncoderAndDecoder() {

        $data = json_encode(array(
            'foo' => 'bar',
            'baz' => 'plic',
            'false' => true,
            'true' => 'false',
            'good' => 'bad',
        ));

        $encodedData = Base64::encode($data);
        $decodedData = Base64::decode($encodedData);

        $this->assertEquals($data, $decodedData);
        $this->assertEquals($data, $decodedData);
        $this->assertRegExp('/^[a-zA-Z0-9+\/]+$/', $encodedData);
    }

    public function testDecoderWithTrailingEqualSign() {

        $data = 'eyJhbGciOiJ0ZXN0In0=';

        $decodedData = Base64::decode($data);
        $encodedData = Base64::encode($decodedData);

        $this->assertEquals('{"alg":"test"}', $decodedData);
        $this->assertNotEquals($data, $encodedData);
        $this->assertRegExp('/^[a-zA-Z0-9+\/]+$/', $encodedData);
    }
}
