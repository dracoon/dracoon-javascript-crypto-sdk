export type SupportedPrf = 'hmacWithSHA1' | 'hmacWithSHA256' | 'hmacWithSHA384' | 'hmacWithSHA512';

export type SupportedHashAlgorithm = SupportedPrf extends `hmacWithSHA${infer num}` ? `SHA-${num}` : never;

export type SupportedCipher = `aes${ValidKeyLength}-CBC`;

export type SupportedCipherType = 'AES-CBC';

//https://developer.mozilla.org/en-US/docs/Web/API/AesKeyGenParams
export type ValidKeyLength = 128 | 192 | 256;

export type ValidKeyByteLength = 16 | 24 | 32;

export type EncryptPrivateKeyConfig = { hashingParams: EncryptPrivateKeyHashingParams; encryptParams: EncryptPrivateKeyEncryptionParams };

export type EncryptPrivateKeyParams = {
    password: string;
    contentToEncrypt: Uint8Array;
    contentEncryptionAlgorithm: EncryptPrivateKeyEncryptionParams;
    hashingParams: EncryptPrivateKeyHashingParams;
};

export type EncryptPrivateKeyHashingParams = {
    salt: Uint8Array;
    hmacHashAlgorithm: SupportedHashAlgorithm;
    iterationCount: number;
};

export type DecryptionParams = {
    hashAlgorithm: SupportedPrf;
    iv: string;
    derivedKeyLengthBytes: ValidKeyByteLength;
    salt: string;
    iterationCount: number;
    cipherName: SupportedCipher;
};

export type DeriveKeyParams = Pick<EncryptPrivateKeyParams, 'password' | 'hashingParams'> & {
    contentEncryptionAlgorithm: AesCBCKeyGenParams;
};

export type EncryptKeyParams = Pick<EncryptPrivateKeyParams, 'contentToEncrypt'> & {
    cryptoKey: CryptoKey;
    contentEncryptionAlgorithm: AesCBCEncryptParams;
};

export type EncryptPrivateKeyEncryptionParams = AesCBCKeyGenParams & AesCBCEncryptParams;

export type AesCBCKeyGenParams = AesKeyGenParams & {
    name: SupportedCipherType;
    length: ValidKeyLength;
};

/**
 * @member iv: Must have length 16
 */
export type AesCBCEncryptParams = AesKeyGenParams & {
    name: SupportedCipherType;
    iv: Uint8Array;
};
