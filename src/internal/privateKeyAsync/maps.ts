import { SupportedCipher, SupportedHashAlgorithm, SupportedPrf, ValidKeyByteLength } from './models';

export const PrfToHashAlg: Readonly<Record<SupportedPrf, SupportedHashAlgorithm>> = Object.freeze({
    hmacWithSHA1: 'SHA-1',
    hmacWithSHA256: 'SHA-256',
    hmacWithSHA384: 'SHA-384',
    hmacWithSHA512: 'SHA-512'
});

export const HashAlgToPrf: Readonly<Record<SupportedHashAlgorithm, SupportedPrf>> = Object.freeze({
    'SHA-1': 'hmacWithSHA1',
    'SHA-256': 'hmacWithSHA256',
    'SHA-384': 'hmacWithSHA384',
    'SHA-512': 'hmacWithSHA512'
});

export const CipherByteLengthMap: Readonly<Record<SupportedCipher, ValidKeyByteLength>> = Object.freeze({
    'aes128-CBC': 16,
    'aes192-CBC': 24,
    'aes256-CBC': 32
});
