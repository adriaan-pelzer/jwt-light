const fs = require('fs');
const crypto = require('crypto');

const generateRSAKeyPair = modulusLength => new Promise((resolve, reject) => crypto.generateKeyPair('rsa', {
  modulusLength: modulusLength || 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
}, (error, publicKey, privateKey) => error
  ? reject(error)
  : resolve({ publicKey, privateKey })
));

const writeFile = (fileName, fileData) => new Promise((resolve, reject) => fs.writeFile(
  fileName,
  fileData,
  error => {
    return error ? reject(error) : resolve(fileName)
  }
));

const readFile = fileName => new Promise((resolve, reject) => fs.readFile(
  fileName,
  (error, data) => {
    return error ? reject(error) : resolve(data.toString())
  }
));

const base64UrlEncodeBuffer = buffer => buffer.toString('base64')
  .replace(/\x2B/g, '-')
  .replace(/\x2F/g, '_')
  .replace(/\x3D/g, '');

const base64UrlEncode = string => base64UrlEncodeBuffer(Buffer.from(string));

const base64UrlDecode = string => Buffer.from(string
  .replace(/\x2D/g, '+')
  .replace(/\x5F/g, '/'),
  'base64'
);

const sign = (payload, privateKey) => (headerPayloadEncoded => ([
  headerPayloadEncoded,
  base64UrlEncodeBuffer(crypto.sign('sha256', Buffer.from(headerPayloadEncoded), {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING
  }))
]).join('.'))([
  { typ: 'JWT', alg: 'RSA' }, payload
].map(JSON.stringify).map(base64UrlEncode).join('.'));

const verify = (jwt, publicKey) => (([
  header, payload, signature
]) => crypto.verify('sha256', Buffer.from(`${header}.${payload}`), {
  key: publicKey,
  padding: crypto.constants.RSA_PKCS1_PSS_PADDING
}, base64UrlDecode(signature)))(jwt.split('.'));

const decode = jwt => JSON.parse(base64UrlDecode(jwt.replace(/^[^\.]*\./, '').replace(/\..*$/, '')).toString());

module.exports = { generateRSAKeyPair, writeFile, readFile, sign, verify, decode };

if (!module.parent) {
  const assert = require('assert');
  const testCtx = {};
  [
    {
      name: 'rsa key pair generation: PEM',
      action: () => generateRSAKeyPair(),
      test: () => ({ publicKey, privateKey }) => {
        assert.match(privateKey, /^-----BEGIN PRIVATE KEY-----.*-----END PRIVATE KEY-----\n$/s);
        assert.match(publicKey, /^-----BEGIN PUBLIC KEY-----.*-----END PUBLIC KEY-----\n$/s);
      },
      store: ({ publicKey, privateKey }) => ({ publicKey, privateKey })
    },
    {
      name: 'save keys',
      action: ({ publicKey, privateKey }) => Promise.all([
        writeFile('private.pem', privateKey),
        writeFile('public.pem', publicKey)
      ]),
      store: ([privateKeyFile, publicKeyFile]) => ({ privateKeyFile, publicKeyFile })
    },
    {
      name: 'load keys',
      action: ({ privateKeyFile, publicKeyFile }) => Promise.all([
        readFile('private.pem'),
        readFile('public.pem')
      ]),
      test: ({ privateKey, publicKey }) => ([newPrivateKey, newPublicKey]) => {
        assert.strictEqual(privateKey, newPrivateKey);
        assert.strictEqual(publicKey, newPublicKey);
      },
      store: ([privateKey, publicKey]) => ({ privateKey, publicKey })
    },
    {
      name: 'generate jwt',
      action: ({ privateKey }) => Promise.resolve(sign({ iss: 'asdf', sub: 'hallo' }, privateKey)),
      test: () => jwt => {
        assert.match(jwt, /^[0-9A-Za-z_-]*\.[0-9A-Za-z_-]*\.[0-9A-Za-z_-]*$/);
      },
      store: jwt => ({ jwt })
    },
    {
      name: 'verify jwt',
      action: ({ jwt, publicKey }) => Promise.resolve(verify(jwt, publicKey)),
      test: () => assert
    },
    {
      name: 'decode jwt',
      action: ({ jwt }) => Promise.resolve(decode(jwt)),
      test: () => ({ iss, sub }) => {
        assert(iss === 'asdf');
        assert(sub === 'hallo');
      }
    }
  ].reduce((chain, { name, action, test = () => () => {}, store = () => ({}) }) => chain
    .then(exitCode => {
      console.log(`o ${name}`);
      return exitCode;
    })
    .then(exitCode => action(testCtx)
      .then(result => {
        test(testCtx)(result);
        console.log(`✓ success`);
        return result;
      })
      .then(store)
      .then(newCtx => Object.keys(newCtx).forEach(key => testCtx[key] = newCtx[key]))
      .then(() => exitCode)
      .catch(error => {
        console.log(JSON.stringify(error));
        console.log(`✘ failure`);
        return 1;
      })
    ),
    Promise.resolve(0)
  )
}
