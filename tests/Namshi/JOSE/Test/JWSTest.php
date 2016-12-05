<?php

namespace Namshi\JOSE\Test;

use DateTime;
use Namshi\JOSE\JWS;
use PHPUnit_Framework_TestCase as TestCase;
use Prophecy\Argument;
use Namshi\JOSE\Signer\OpenSSL\HS256;
use Namshi\JOSE\Base64\Base64UrlSafeEncoder;

class JWSTest extends TestCase
{
    const SSL_KEY_PASSPHRASE = 'tests';

    public function setup()
    {
        $date = new DateTime('tomorrow');
        $data = array(
            'a' => 'b',
        );
        $this->jws = new JWS(array('alg' => 'RS256'));
        $this->jws->setPayload($data);
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testLoadingUnsecureJwsWithNoneAlgo()
    {
        $date = new DateTime('tomorrow');
        $data = array(
            'a' => 'b',
            'exp' => $date->format('U'),
        );
        $this->jws = new JWS(array('alg' => 'None'));
        $this->jws->setPayload($data);
        $this->jws->sign('111');

        $jws = JWS::load($this->jws->getTokenString());
        $this->assertFalse($jws->verify('111'));

        $payload = $jws->getPayload();
        $this->assertEquals('b', $payload['a']);
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testLoadingUnsecureJwsWithLowercaseNone()
    {
        $date = new DateTime('tomorrow');
        $data = array(
            'a' => 'b',
            'exp' => $date->format('U'),
        );
        $this->jws = new JWS(array('alg' => 'none'));
        $this->jws->setPayload($data);
        $this->jws->sign('111');

        $jws = JWS::load($this->jws->getTokenString());
        $this->assertFalse($jws->verify('111'));

        $payload = $jws->getPayload();
        $this->assertEquals('b', $payload['a']);
    }

    public function testAllowingUnsecureJws()
    {
        $date = new DateTime('tomorrow');
        $data = array(
            'a' => 'b',
            'exp' => $date->format('U'),
        );
        $this->jws = new JWS(array('alg' => 'None'));
        $this->jws->setPayload($data);
        $this->jws->sign('111');

        $jws = JWS::load($this->jws->getTokenString(), true);
        $this->assertTrue($jws->verify('111'));

        $payload = $jws->getPayload();
        $this->assertEquals('b', $payload['a']);
    }

    public function testRestrictingTheAlgorithmsKo()
    {
        $this->jws = new JWS(array('alg' => 'HS256'));
        $this->jws->sign('12345');

        $jws = JWS::load($this->jws->getTokenString());
        $this->assertFalse($jws->verify('12345', 'RS256'));
    }

    public function testRestrictingTheAlgorithmsOk()
    {
        $date = new DateTime('tomorrow');
        $data = array(
            'a' => 'b',
            'exp' => $date->format('U'),
        );
        $this->jws = new JWS(array('alg' => 'HS256'));
        $this->jws->setPayload($data);
        $this->jws->sign('123');

        $jws = JWS::load($this->jws->getTokenString());
        $this->assertTrue($jws->verify('123', 'HS256'));
    }

    public function testVerificationRS256()
    {
        $privateKey = openssl_pkey_get_private(SSL_KEYS_PATH.'private.key', self::SSL_KEY_PASSPHRASE);
        $this->jws->sign($privateKey);

        $jws = JWS::load($this->jws->getTokenString());
        $public_key = openssl_pkey_get_public(SSL_KEYS_PATH.'public.key');
        $this->assertTrue($jws->verify($public_key));

        $payload = $jws->getPayload();
        $this->assertEquals('b', $payload['a']);
    }

    public function testVerificationRS256KeyAsString()
    {
        $privateKey = file_get_contents(TEST_DIR.'/private.key');
        $this->jws->sign($privateKey, self::SSL_KEY_PASSPHRASE);

        $jws = JWS::load($this->jws->getTokenString());
        $public_key = openssl_pkey_get_public(SSL_KEYS_PATH.'public.key');
        $this->assertTrue($jws->verify($public_key));

        $payload = $jws->getPayload();
        $this->assertEquals('b', $payload['a']);
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

    public function testVerificationThatTheJWSIsSigned()
    {
        $privateKey = openssl_pkey_get_private(SSL_KEYS_PATH.'private.key', self::SSL_KEY_PASSPHRASE);
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
        $privateKey = openssl_pkey_get_private(SSL_KEYS_PATH.'private.key', self::SSL_KEY_PASSPHRASE);
        $this->jws->sign($privateKey);

        $jws = JWS::load('eyJhbGciOiJ0ZXN0In0=.eyJhbGciOiJ0ZXN0In0=.eyJhbGciOiJ0ZXN0In0=');
        $public_key = openssl_pkey_get_public(SSL_KEYS_PATH.'public.key');
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
        $jwsHMAC = new JWS(array('alg' => 'HS256'));

        $jwsHMAC->sign(false);
        $jws = JWS::load($jwsHMAC->getTokenString());

        $this->assertFalse($jws->verify($public_key));
    }

    public function testSignAndVerifyWithEmptyStringPublicKey()
    {
        $public_key = false;
        $jwsHMAC = new JWS(array('alg' => 'HS256'));

        $jwsHMAC->sign('');
        $jws = JWS::load($jwsHMAC->getTokenString());

        $this->assertFalse($jws->verify($public_key));
    }

    public function testLoadingWithAnyOrderOfHeaders()
    {
        $privateKey = openssl_pkey_get_private(SSL_KEYS_PATH.'private.key', self::SSL_KEY_PASSPHRASE);
        $public_key = openssl_pkey_get_public(SSL_KEYS_PATH.'public.key');

        $this->jws = new JWS(array('alg' => 'RS256', 'custom' => '1'));

        $header = $this->jws->getHeader();
        $reversedHeader = array_reverse($header);
        $this->assertFalse($header === $reversedHeader);

        $this->jws->setHeader($reversedHeader);
        $this->jws->sign($privateKey);

        $tokenString = $this->jws->getTokenString();
        $jws = JWS::load($tokenString);
        $this->assertTrue($reversedHeader === $jws->getHeader());
    }

    public function testSignAndVerifyWithSecLib()
    {
        if (version_compare(PHP_VERSION, '7.0.0-dev') >= 0) {
            $this->setExpectedException('InvalidArgumentException');
        }

        $jwsRSA = new JWS(array('alg' => 'RS256'), 'SecLib');
        $data = array('a' => 'b');
        $jwsRSA->setPayload($data);

        $jwsRSA->sign(file_get_contents(SSL_KEYS_PATH.'private.key'), 'tests');
        $jws = JWS::load($jwsRSA->getTokenString(), false, null, 'SecLib');

        $this->assertTrue($jws->verify(file_get_contents(SSL_KEYS_PATH.'public.key', 'RS256')));
    }

    public function testConstructionFromHeader()
    {
        $header = array('alg' => 'RS256', 'test' => true);
        $jws = new JWS($header);

        $this->assertTrue($header == $jws->getHeader());
    }

    public function testVerificationCustomizedHeader()
    {
        $header = $this->jws->getHeader();
        $header['test'] = true;
        $this->jws->setHeader($header);

        $privateKey = openssl_pkey_get_private(SSL_KEYS_PATH.'private.key', self::SSL_KEY_PASSPHRASE);
        $this->jws->sign($privateKey);

        $jws = JWS::load($this->jws->getTokenString());
        $public_key = openssl_pkey_get_public(SSL_KEYS_PATH.'public.key');
        $headerFromSig = $jws->getHeader();

        $this->assertSame($headerFromSig['test'], true);
        $this->assertTrue($jws->verify($public_key));
    }

    public function testVerificationWithJsonThatContainsWhitespace()
    {
        $header = '{
            "alg": "HS256"
        }';

        $payload = '{
            "a": "b"
        }';

        $encoder = new Base64UrlSafeEncoder();
        $signer = new HS256();

        $token = sprintf('%s.%s', $encoder->encode($header), $encoder->encode($payload));
        $signature = $encoder->encode($signer->sign($token, '123'));
        $jwsToken = sprintf('%s.%s', $token, $signature);

        $jws = JWS::load($jwsToken);

        $this->assertTrue($jws->verify('123'));
    }
}
