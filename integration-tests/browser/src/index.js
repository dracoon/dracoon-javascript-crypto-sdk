//@ts-check
import { Crypto, UserKeyPairVersion } from '@dracoon-official/crypto-sdk';

Crypto.generateUserKeyPair(UserKeyPairVersion.RSA4096, 'B').then(() => {
    console.log('generateUserKeyPair - ok!');
});
