<?php

$loader = require __DIR__.'/../vendor/autoload.php';
$loader->add('Namshi\\JOSE\\Test', __DIR__);

define('TEST_DIR', __DIR__);
define('SSL_KEYS_PATH', 'file://'.TEST_DIR.DIRECTORY_SEPARATOR);
