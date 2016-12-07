### 6.1.0

- Dropped support for PHP 5.4
- phpseclib ~2.0.x

### 6.0.4

- Added styleci config, add styleci-php-cs bridge to check formatting
- Removed composer.lock
- Fix #34: strlen() and substr() can misbehave with mbstring.func_overload
- Fix: Don't cast to boolean the result of openssl_verify()
- Enhancement: support phpseclib 1.x.x

### 6.x.x - Not Backwards Compatible

- Dropped support for PHP 5.3
- Don't escape slashes when generating signin input.
  This may render tokens generated with earlier versions of Jose incompatible.
- **DON'T** install version 6.0.2! It's using phpseclib version 2 instead of version 1 and some classes are broken

### 3.x.x to 4.x.x - Not Backwards Compatible

Added the ability to set custom properties in the header. Moved automatic inclusion of certain claims into an SimpleJWS class from the base JWS class.

### 2.x.x to 3.x.x

Introduced the ability to specify an encryption engine. Added support of PHPSecLib to the existing OpenSSL implementation.

