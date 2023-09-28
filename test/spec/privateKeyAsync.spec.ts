import { decryptRsaPrivateKeyAsync } from '../../src/internal/privateKeyAsync/decryptPrivateKeyAsync';
import { encryptRsaPrivateKeyAsync } from '../../src/internal/privateKeyAsync/encryptPrivateKeyAsync';
import { getCryptoWorker } from '../../src/internal/privateKeyAsync/getCryptoWorker';
import { SupportedCipherType, SupportedHashAlgorithm, ValidKeyLength } from '../../src/internal/privateKeyAsync/models';
import keypair_4096_2 from '../keys/javascript/kp_rsa4096_2/kp_rsa4096_2.json';

describe('Roundtrip: Crypto.encryptPrivateKeyAsync -> Crypto.decryptPrivateKeyAsync', () => {
    const crypto: Crypto = getCryptoWorker();
    const { algorithm, password } = keypair_4096_2.config;
    const plainPrivateKey: string = keypair_4096_2.plainUserKeyPairContainer.privateKeyContainer.privateKey;

    it.each<{ keyLength: ValidKeyLength; prf: SupportedHashAlgorithm; count: number }>([
        { count: 1.3e6, prf: 'SHA-1', keyLength: 128 },
        { count: 1.3e6, prf: 'SHA-1', keyLength: 192 },
        { count: 1.3e6, prf: 'SHA-1', keyLength: 256 },
        { count: 6e5, prf: 'SHA-256', keyLength: 128 },
        { count: 6e5, prf: 'SHA-256', keyLength: 192 },
        { count: 6e5, prf: 'SHA-256', keyLength: 256 },
        { count: 4e5, prf: 'SHA-384', keyLength: 128 },
        { count: 4e5, prf: 'SHA-384', keyLength: 192 },
        { count: 4e5, prf: 'SHA-384', keyLength: 256 },
        { count: 2.1e5, prf: 'SHA-512', keyLength: 128 },
        { count: 2.1e5, prf: 'SHA-512', keyLength: 192 },
        { count: 2.1e5, prf: 'SHA-512', keyLength: 256 },
        { count: 1e4, prf: 'SHA-1', keyLength: 128 },
        { count: 1e4, prf: 'SHA-1', keyLength: 192 },
        { count: 1e4, prf: 'SHA-1', keyLength: 256 },
        { count: 1e4, prf: 'SHA-256', keyLength: 128 },
        { count: 1e4, prf: 'SHA-256', keyLength: 192 },
        { count: 1e4, prf: 'SHA-256', keyLength: 256 },
        { count: 1e4, prf: 'SHA-384', keyLength: 128 },
        { count: 1e4, prf: 'SHA-384', keyLength: 192 },
        { count: 1e4, prf: 'SHA-384', keyLength: 256 },
        { count: 1e4, prf: 'SHA-512', keyLength: 128 },
        { count: 1e4, prf: 'SHA-512', keyLength: 192 },
        { count: 1e4, prf: 'SHA-512', keyLength: 256 }
    ])('should work for prf: $prf, keylength: $keyLength, count: $count', async ({ prf, count, keyLength }) => {
        const salt: Uint8Array = new Uint8Array(16);
        crypto.getRandomValues(salt);
        const iv: Uint8Array = new Uint8Array(16);
        crypto.getRandomValues(iv);

        const encrypted: string = await encryptRsaPrivateKeyAsync(
            plainPrivateKey,
            password,
            {
                hashingParams: { iterationCount: count, hmacHashAlgorithm: prf, salt },
                encryptParams: { iv, length: keyLength, name: algorithm as SupportedCipherType }
            },
            crypto
        );
        const decrypted: string = await decryptRsaPrivateKeyAsync(encrypted, password, crypto);

        expect(plainPrivateKey).toEqual(decrypted);
    });
});
