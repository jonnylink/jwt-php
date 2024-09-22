# jwt-php
A tiny library for jwt auth with no dependencies.

## installation
Install via packagist & composer:
`composer require jonlink/jwt`

## usage
Create a new JWT and get the token:
```
$jwt = new JwtPhp(
    payload: (object) ['foo' => 'bar'],
    secret: 'abc',
);

echo $jwt->getToken();
```

Validate a JWT:
```
$jwt = new JwtPhp(
    token: 123.abc.123,
    secret: 'foo',
);

echo $jwt->isValid() ? 'this is valid' : 'this is NOT valid';
```

Update a supported (reserved) claim:
```
$jwt = new JwtPhp(
    token: 123.abc.123,
    secret: 'foo',
);

$jwt->setExpiration(123);
$jwt->setSupportedClaim('exp', 123);
```

Update a non-supported claim:
```
$jwt = new JwtPhp(
    token: 123.abc.123,
    secret: 'foo',
);

$jwt->setClaim('funnyClaim', 'hello world');
```
