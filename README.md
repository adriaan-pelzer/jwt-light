# jwt-light
A lightweight jwt implementation - one that depends only on core modules

## Installation

```
  npm install jwt-light
```
or
```
  yarn add jwt-light
```

## Usage

### Generate and save RSA keys

```js
  const { generateRSAKeyPair, writeFile } = require('jwt-light');
  
  return generateRSAKeyPair()
    .then(({ privateKey, publicKey }) => Promise.all([
      writeFile('private.pem', privateKey),
      writeFile('public.pem', publicKey)
    ]));
```

### Encode and sign jwt token with private key

```js
  const { readFile, sign } = require('jwt-light');
  
  return readFile('private.pem')
    .then(privateKey => {
      const jwt = sign({ iss: 'issuer', aud: 'audience', sub: 'subject' }, privateKey);
      // store jwt somewhere
    });
```

### Verify and decode jwt with public key

```js
  const { readFile, verify, decode } = require('jwt-light');

  return readFile('public.pem')
    .then(publicKey => {
      // get jwt from somewhere
      if (!verify(jwt, publicKey)) {
        throw new Error('jwt did not pass verification');
      }
      const { iss, aud, sub } = decode(jwt);
    });
```
