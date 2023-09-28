[![CI](https://github.com/dracoon/dracoon-javascript-crypto-sdk/actions/workflows/main.yml/badge.svg)](https://github.com/dracoon/dracoon-javascript-crypto-sdk/actions)
[![Node version](https://img.shields.io/npm/v/@dracoon-official/crypto-sdk)](https://npmjs.com/package/@dracoon-official/crypto-sdk)

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

-   Node v16+

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

IMPORTANT: please create a new file key for every file you encrypt!
IMPORTANT: please call doFinal() to complete decryption BEFORE using the decrypted data!

```javascript
import { Crypto, EncryptedDataContainer, PlainDataContainer, PlainFileKeyVersion, UserKeyPairVersion } from '@dracoon-official/crypto-sdk';

/**
 * This file shows how to use the Dracoon JavaScript Crypto SDK.
 * For the sake of simplicity, error handling is ignored.
 *
 * IMPORTANT: please create a new file key for every file you encrypt!
 * IMPORTANT: please call doFinal() to complete decryption BEFORE using the decrypted data!
 */

const CHUNK_SIZE_BYTES = 16;
const DATA = new Uint8Array(CHUNK_SIZE_BYTES ** 2);
const USER_PASSWORD = 'Password1234!';

/**
 * Shows a complete encryption/decryption workflow.
 */
const performEncryptionDecryptionWorkflow = async () => {
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
    const success = await Crypto.checkUserKeyPairAsync(userKeyPair, USER_PASSWORD);
    if (!success) {
        console.log('wrong password');
        return;
    }
    // Decrypt private key
    const plainUserKeyPair = await Crypto.decryptPrivateKeyAsync(userKeyPair, USER_PASSWORD);
    // Decrypt file key
    const decryptedFileKey = Crypto.decryptFileKey(encryptedFileKey, plainUserKeyPair.privateKeyContainer);

    // --- DECRYPTION ---
    // Perform Decryption
    const decryptedData = performDecryption(decryptedFileKey, encryptedData);
    console.log('decryptedData', decryptedData);
};

/**
 * Shows the encryption workflow.
 */
const performEncryption = (plainFileKey, plainData) => {
    // Generate file encryption cipher
    const fileEncryptionCipher = Crypto.createFileEncryptionCipher(plainFileKey);

    // Split up data into chunks
    const plainChunks = [];
    for (let startIndex = 0; startIndex < plainData.length; startIndex += CHUNK_SIZE_BYTES) {
        const endIndex = startIndex + CHUNK_SIZE_BYTES;
        plainChunks.push(plainData.slice(startIndex, endIndex));
    }

    // Encrypt chunks
    const encryptedChunks = [];
    plainChunks.forEach((chunk) => {
        const encryptedDataContainer = fileEncryptionCipher.processBytes(new PlainDataContainer(chunk));
        encryptedChunks.push(encryptedDataContainer.getContent());
    });

    // Complete encryption and get authentication tag
    plainFileKey.tag = fileEncryptionCipher.doFinal().getTag();

    // Concatenate encrypted chunks
    const concatenatedChunks = [];
    encryptedChunks.forEach((chunk) => {
        concatenatedChunks.push(...chunk);
    });
    const encryptedData = new Uint8Array(concatenatedChunks);

    return encryptedData;
};

/**
 * Shows the decryption workflow.
 */
const performDecryption = (plainFileKey, encryptedData) => {
    // Create file decryption cipher
    const fileDecryptionCipher = Crypto.createFileDecryptionCipher(plainFileKey);

    // Split up data into chunks
    const encryptedChunks = [];
    for (let startIndex = 0; startIndex < encryptedData.length; startIndex += CHUNK_SIZE_BYTES) {
        const endIndex = startIndex + CHUNK_SIZE_BYTES;
        encryptedChunks.push(encryptedData.slice(startIndex, endIndex));
    }

    // Decrypt chunks
    const decryptedChunks = [];
    encryptedChunks.forEach((chunk) => {
        const plainDataContainer = fileDecryptionCipher.processBytes(new EncryptedDataContainer(chunk));
        decryptedChunks.push(plainDataContainer.getContent());
    });

    // Complete decryption and get final chunk
    const plainDataContainer = fileDecryptionCipher.doFinal();
    decryptedChunks.push(plainDataContainer.getContent());

    // Concatenate decrypted chunks
    const concatenatedChunks = [];
    decryptedChunks.forEach((chunk) => {
        concatenatedChunks.push(...chunk);
    });
    const decryptedData = new Uint8Array(concatenatedChunks);

    return decryptedData;
};

performEncryptionDecryptionWorkflow();
```

# Copyright and License

Copyright 2021 Dracoon GmbH. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
