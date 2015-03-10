# NAMSHI | JOSE

[![Build Status](https://travis-ci.org/namshi/jose.png?branch=master)](https://travis-ci.org/namshi/jose)
[![HHVM Status](http://hhvm.h4cc.de/badge/namshi/jose.png)](http://hhvm.h4cc.de/package/namshi/jose)

[![SensioLabsInsight](https://insight.sensiolabs.com/projects/4beaf3d1-0bc6-4869-b99f-71dc951a2a05/mini.png)](https://insight.sensiolabs.com/projects/4beaf3d1-0bc6-4869-b99f-71dc951a2a05)

This library provides a lightweight
implementation of the JWS
([JSON Web Signature](http://tools.ietf.org/html/draft-jones-json-web-signature-04)) specification.

## Prerequisites

This library needs PHP 5.4+ and the library OpenSSL.

It has been tested using `PHP5.3` to `PHP5.6` and `HHVM`.


## Installation

You can install the library directly from
composer / [packagist](https://packagist.org/packages/namshi/jose):

```
"namshi/jose": "2.1.*"
```

## Usage

Using it is pretty straightforward:
imagine that you want to offer a service
the ability to authenticate a user via
a cookie, and the service is built with
javascript; what you would need to do is
to generate a JWS (after verifying the
credentials once), store it as a cookie
and then pass it from your JavaScript app
everytime you want to authenticate that
user.

First, generate the JWS:

``` php
<?php

use Namshi\JOSE\JWS;

if ($username == 'correctUsername' && $pass == 'ok') {
	$user = Db::loadUserByUsername($username);

	$jws  = new JWS('RS256');
	$jws->setPayload(array(
		'uid' => $user->getid(),
	));

    $privateKey = openssl_pkey_get_private("file://path/to/private.key", self::SSL_KEY_PASSPHRASE);
    $jws->sign($privateKey);
    setcookie('identity', $jws->getTokenString());
}
```

Then your JS app can use the available cookie to execute
authenticated calls, without sending passwords or credentials.

Once a request is submitted, you only have to verify that it
is a valid call:

``` php
<?php

use Namshi\JOSE\JWS;

$jws        = JWS::load($_COOKIE['identity']);
$public_key = openssl_pkey_get_public("/path/to/public.key");

// verify that the token is valid and had the same values
// you emitted before while setting it as a cookie
if ($jws->isValid($public_key, 'RS256')) {
	$payload = $jws->getPayload();

	echo sprintf("Hey, my JS app just did an action authenticated as user #%s", $payload['id']);
}
```

> PROTIP: you can omit the second argument of the isValid() method, so jose will try to validate the token with the algorithm specified in the token's header, though this might expose you to some security issues.
>
> For now we recommend to always explicitely set the algorithm you want to use to validate tokens.

## Under the hood

In order to [validate the JWS](https://github.com/namshi/jose/blob/master/src/Namshi/JOSE/JWS.php#L126),
the signature is first [verified](https://github.com/namshi/jose/blob/master/src/Namshi/JOSE/JWS.php#L110)
with a public key and then we will check whether the [token is expired](https://github.com/namshi/jose/blob/master/src/Namshi/JOSE/JWS.php#L172).

To give a JWS a TTL, just use the standard `exp` value in the payload:

``` php
$date    	= new DateTime('tomorrow');
$this->jws  = new JWS('RS256');
$this->jws->setPayload(array(
	'exp' => $date->format('U'),
));
```

### Unsecure JWSes

You can allow [unsecure JWSes](https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#page-12)
by setting the `$allowUnsecure` flag while loading JWSes:

``` php
JWS::load($this->jws->getTokenString(), true);
```

This allows tokens signed with the 'none' algorithms to go through, which is something
you probably don't want to do. Proceed with caution :)

**Unsecure JWSes are disabled by default since version 2.1.2. You should not
use previous versions other than 1.0.2, 1.1.2, 2.0.3 as they have a security
vulnerability. More info [here](http://tech.namshi.com/blog/2015/02/19/update-your-namshi-slash-jose-installations-as-a-security-vulnerability-was-found/).**

## Using a custom encoder

If, for some reason, you need to encode the token in a different way, you can
inject any implementation of `Namshi\JOSE\Base64\Encoder` in a `JWS` instance.
Likewise, `JWS::load()` accepts such an implementation as a second argument.

## Credits

This library has been inspired by the
[initial work done by @ritou](https://github.com/ritou/php-Akita_JOSE).
