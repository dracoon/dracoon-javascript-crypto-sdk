//@ts-check
const dc = require('@dracoon-official/crypto-sdk');
const Crypto = dc.Crypto;
const UserKeyPairVersion = dc.UserKeyPairVersion;

Crypto.generateUserKeyPair(UserKeyPairVersion.RSA4096, 'my-secret-dummy-pw-that-nobody-nows').then(() => {
    console.log('generateUserKeyPair - ok!');
});
