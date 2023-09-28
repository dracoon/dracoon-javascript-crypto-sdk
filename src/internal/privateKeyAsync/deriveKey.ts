import { DeriveKeyParams } from './models';

export async function deriveKey(parameters: DeriveKeyParams, cryptoWorker: Crypto): Promise<CryptoKey> {
    const passwordView: Uint8Array = new TextEncoder().encode(parameters.password);
    const pbkdfKey: CryptoKey = await cryptoWorker.subtle.importKey('raw', passwordView, 'PBKDF2', false, ['deriveKey']);
    const derivedKey: CryptoKey = await cryptoWorker.subtle.deriveKey(
        {
            name: 'PBKDF2',
            hash: {
                name: parameters.hashingParams.hmacHashAlgorithm
            },
            salt: parameters.hashingParams.salt,
            iterations: parameters.hashingParams.iterationCount
        },
        pbkdfKey,
        parameters.contentEncryptionAlgorithm,
        true,
        ['encrypt', 'decrypt']
    );
    return derivedKey;
}
