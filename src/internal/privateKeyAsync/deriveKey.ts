import { DeriveKeyParams } from './models';
import { Encoding } from '../../models/Encoding.enum';
import { Utils } from './utils';

export async function deriveKey(parameters: DeriveKeyParams, cryptoWorker: Crypto, encoding: Encoding = Encoding.UTF8): Promise<CryptoKey> {
    let passwordView = new Uint8Array();
    if (encoding === Encoding.UTF8) {
        passwordView = new TextEncoder().encode(parameters.password);
    }
    if (encoding === Encoding.ISO8859) {
        passwordView = Utils.encodeISO(parameters.password);
    }
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
