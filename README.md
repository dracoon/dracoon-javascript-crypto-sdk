# Dracoon JavaScript Crypto SDK

A library which implements the client-side encryption of Dracoon.

# Introduction

A document which describes the client-side encryption in detail can be found here:

https://support.dracoon.com/hc/en-us/articles/360000986345

# System Requirements

The following Browser versions are officially supported:

-   Chrome v89+
-   Edge v89+
-   Firefox v87+
-   Safari v14+

The following Node versions are officially supported:

-   Node v14+

Older Browser/Node versions might still work, but have not been tested.

# Setup

#### Download & Installation

The package is available on the [npm Registry](https://npmjs.com/package/@dracoon-official/crypto-sdk) and can be installed using `npm`.

```shell
npm install --save @dracoon-official/crypto-sdk
```

##### Import

CommonJS

```javascript
const { Crypto } = require('@dracoon-official/crypto-sdk');
```

ES Modules

```javascript
import { Crypto } from '@dracoon-official/crypto-sdk';
```

# Example

An example can be found here: `example/program.js`

The example shows the complete encryption/decryption workflow, including key generation and key operations.

```javascript
...

// Get plain data
const plainData = new Uint8Array([...DATA]);
console.log('plainData', plainData);

// --- KEY GENERATION ---
// Generate key pair
const userKeyPair = await Crypto.generateUserKeyPair(UserKeyPairVersion.RSA4096, USER_PASSWORD);
// Generate plain file key
const plainFileKey = Crypto.generateFileKey(PlainFileKeyVersion.AES256GCM);

// --- ENCRYPTION ---
// Perform Encryption
const encryptedData = performEncryption(plainFileKey, plainData);
console.log('encryptedData', encryptedData);

// --- KEY OPERATIONS ---
// Encrypt file key
const encryptedFileKey = Crypto.encryptFileKey(plainFileKey, userKeyPair.publicKeyContainer);
// Check password
const success = Crypto.checkUserKeyPair(userKeyPair, USER_PASSWORD);
if (!success) {
    console.log('wrong password');
    return;
}
// Decrypt private key
const plainUserKeyPair = Crypto.decryptPrivateKey(userKeyPair, USER_PASSWORD);
// Decrypt file key
const decryptedFileKey = Crypto.decryptFileKey(encryptedFileKey, plainUserKeyPair.privateKeyContainer);

// --- DECRYPTION ---
// Perform Decryption
const decryptedData = performDecryption(decryptedFileKey, encryptedData);
console.log('decryptedData', decryptedData);

...
```

# Copyright and License

Copyright 2021 Dracoon GmbH. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
