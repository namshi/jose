# NAMSHI | JOSE

This library provides a lightweight
implementation of the JWS
(JSON Web Signature) specification.

## Installation

You can install the library directly from
composer / packagist.

## Usage

Using it it's pretty straightforward:
imagine that you want to offer a service
the ability to authenticate a user via
a cookie, and the service is built with
javascript; what you would need to do is
to generate a JWS (after verifying the
credentials once), store it as a cookie
and then pass it from your JavaScript app
everytime you want to authenticate that
user.

First, generate the JSW:

``` php
<?php

use Namshi\JOSE\JWS;

if ($username == 'correctUsername' && $pass = 'ok') {
	$user = Db::loadUserByUsername($username);

	$jws  = new JWS('RS256');
	$jws->setPayload(array(
		'uid' => $user->getid(),
	));

    $privateKey = openssl_pkey_get_private("file://path/to/private.key", self::SSL_KEY_PASSPHRASE);;
    setcookie('identity', $jws->sign($privateKey));
}
```

Then your JS app can use the available cookie to execute
authenticated calls, without sending passwords or credentials.

Once a request is submitted, you only have to verify that it
is a verified call:

``` php
<?php

use Namshi\JOSE\JWS;

$jws        = JWS::load($_COOKIE['identity']);
$public_key = openssl_pkey_get_public("/path/to/public.key");

// verify that the token is valid and had the same values
// you emitted before while setting it as a cookie
if ($jws->verify($public_key)) {
	$paylod = $jws->getPayload();

	echo sprintf("Hey, my JS app just did an action authenticated as user #%s", $payload['id']);
}
```