<?php

namespace Namshi\JOSE\Test;

use PHPUnit_Framework_TestCase as TestCase;
use Namshi\JOSE\JWS;
use DateTime;
use Prophecy\Argument;

class JWSTest extends TestCase
{
    const SSL_KEY_PASSPHRASE = 'tests';

    public function setup()
    {
        $date       = new DateTime('tomorrow');
        $data       = array(
            'a'     => 'b',
            'exp'   => $date->format('U')
        );
        $this->jws  = new JWS('RS256');
        $this->jws->setPayload($data);
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testLoadingUnsecureJws()
    {
        $date       = new DateTime('tomorrow');
        $data       = array(
            'a'     => 'b',
            'exp'   => $date->format('U')
        );
        $this->jws  = new JWS('None');
        $this->jws->setPayload($data);
        $this->jws->sign('111');

        $jws        = JWS::load($this->jws->getTokenString());
        $this->assertFalse($jws->verify('111'));

        $payload = $jws->getPayload();
        $this->assertEquals('b', $payload['a']);
    }

    public function testAllowingUnsecureJws()
    {
        $date       = new DateTime('tomorrow');
        $data       = array(
            'a'     => 'b',
            'exp'   => $date->format('U')
        );
        $this->jws  = new JWS('None');
        $this->jws->setPayload($data);
        $this->jws->sign('111');

        $jws        = JWS::load($this->jws->getTokenString(), true);
        $this->assertTrue($jws->verify('111'));

        $payload = $jws->getPayload();
        $this->assertEquals('b', $payload['a']);
    }
    
    public function testRestrictingTheAlgorithmsKo()
    {
        $this->jws  = new JWS('HS256');
        $this->jws->sign('12345');

        $jws        = JWS::load($this->jws->getTokenString());
        $this->assertFalse($jws->verify('12345', 'RS256'));
        $this->assertFalse($jws->isValid('12345', 'RS256'));
    }
    
    public function testRestrictingTheAlgorithmsOk()
    {
        $date       = new DateTime('tomorrow');
        $data       = array(
            'a'     => 'b',
            'exp'   => $date->format('U')
        );
        $this->jws  = new JWS('HS256');
        $this->jws->setPayload($data);
        $this->jws->sign('123');

        $jws        = JWS::load($this->jws->getTokenString());
        $this->assertTrue($jws->verify('123', 'HS256'));
        $this->assertTrue($jws->isValid('123', 'HS256'));
    }

    public function testVerificationRS256()
    {
        $privateKey = openssl_pkey_get_private(SSL_KEYS_PATH . "private.key", self::SSL_KEY_PASSPHRASE);
        $this->jws->sign($privateKey);

        $jws        = JWS::load($this->jws->getTokenString());
        $public_key = openssl_pkey_get_public(SSL_KEYS_PATH . "public.key");
        $this->assertTrue($jws->verify($public_key));

        $payload = $jws->getPayload();
        $this->assertEquals('b', $payload['a']);
    }

    public function testValidationOfAValidJWS()
    {
        $privateKey = openssl_pkey_get_private(SSL_KEYS_PATH . "private.key", self::SSL_KEY_PASSPHRASE);
        $this->jws->sign($privateKey);

        $jws        = JWS::load($this->jws->getTokenString());
        $public_key = openssl_pkey_get_public(SSL_KEYS_PATH . "public.key");
        $this->assertTrue($jws->isValid($public_key));
    }

    public function testUseOfCustomEncoder()
    {
        $encoder = $this->prophesize('Namshi\JOSE\Base64\Encoder');
        $encoder
            ->decode(Argument::any())
            ->willReturn('{"whatever": "the payload should be"}')
            ->shouldBeCalled();
        $encoder
            ->decode(Argument::any())
            ->willReturn('{"alg": "test"}')
            ->shouldBeCalled();
        JWS::load($this->jws->getTokenString(), false, $encoder->reveal());
    }

    public function testValidationOfInvalidJWS()
    {
        $date       = new DateTime('yesterday');
        $this->jws->setPayload(array(
            'exp' => $date->format('U')
        ));
        $privateKey = openssl_pkey_get_private(SSL_KEYS_PATH . "private.key", self::SSL_KEY_PASSPHRASE);
        $this->jws->sign($privateKey);

        $jws        = JWS::load($this->jws->getTokenString());
        $public_key = openssl_pkey_get_public(SSL_KEYS_PATH . "public.key");
        $this->assertFalse($jws->isValid($public_key));
    }

    public function testVerificationThatTheJWSIsSigned()
    {
        $privateKey = openssl_pkey_get_private(SSL_KEYS_PATH . "private.key", self::SSL_KEY_PASSPHRASE);
        $this->jws->sign($privateKey);
        $this->assertTrue($this->jws->isSigned());
    }

    public function testVerificationThatTheJWSIsNotSigned()
    {
        $this->assertFalse($this->jws->isSigned());
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testWrongVerificationRS256()
    {
        $privateKey = openssl_pkey_get_private(SSL_KEYS_PATH . "private.key", self::SSL_KEY_PASSPHRASE);
        $this->jws->sign($privateKey);

        $jws        = JWS::load('eyJhbGciOiJ0ZXN0In0=.eyJhbGciOiJ0ZXN0In0=.eyJhbGciOiJ0ZXN0In0=');
        $public_key = openssl_pkey_get_public(SSL_KEYS_PATH . "public.key");
        $this->assertFalse($jws->verify($public_key));
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testLoadingAMalformedTokenString()
    {
        JWS::load('test.Test.TEST');
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testLoadingAMalformedTokenString2()
    {
        JWS::load('test');
    }

    public function testSignAndVerifyWithFalsePublicKey()
    {
        $public_key = false;
        $jwsHMAC    = new JWS('HS256');

        $jwsHMAC->sign(false);
        $jws = JWS::load($jwsHMAC->getTokenString());

        $this->assertFalse($jws->verify($public_key));

    }

    public function testSignAndVerifyWithEmptyStringPublicKey()
    {
        $public_key = false;
        $jwsHMAC    = new JWS('HS256');

        $jwsHMAC->sign('');
        $jws = JWS::load($jwsHMAC->getTokenString());

        $this->assertFalse($jws->verify($public_key));

    }

}
