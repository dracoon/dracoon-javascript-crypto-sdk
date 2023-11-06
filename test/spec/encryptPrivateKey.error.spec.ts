import { Crypto } from '../../src/index.node';
import { EncryptionError } from '../../src/error/models/EncryptionError';
import { InvalidArgumentError } from '../../src/error/models/InvalidArgumentError';
import { InvalidKeyPairError } from '../../src/error/models/InvalidKeyPairError';
import { PlainUserKeyPairContainer } from '../../src/models/PlainUserKeyPairContainer';
import { PrivateKeyContainer } from '../../src/models/PrivateKeyContainer';
import { PublicKeyContainer } from '../../src/models/PublicKeyContainer';

// Javascript crypto sdk keys
import plainPrivateKey2048 from '../keys/javascript/kp_rsa2048/plain_private_key.json';
import publicKey2048 from '../keys/javascript/kp_rsa2048/public_key.json';
import publicKey4096 from '../keys/javascript/kp_rsa4096/public_key.json';

// Javascript crypto sdk keys (corrupted)
import plainPrivateKeyBadAsn1 from '../keys/corrupted/plain_private_key_bad_asn1.json';
import plainPrivateKeyBadPem from '../keys/corrupted/plain_private_key_bad_pem.json';
import plainPrivateKeyBadVersion from '../keys/corrupted/plain_private_key_bad_version.json';
import publicKeyBadAsn1 from '../keys/corrupted/public_key_bad_asn1.json';
import publicKeyBadPem from '../keys/corrupted/public_key_bad_pem.json';
import publicKeyBadVersion from '../keys/corrupted/public_key_bad_version.json';

type Context = {
    plainUserKeyPairContainer: PlainUserKeyPairContainer;
    password: string;
};

describe('Function: Crypto.encryptPrivateKey', () => {
    let testContext: Context;

    beforeEach(() => {
        testContext = {} as Context;
    });

    describe('with invalid keypair', () => {
        beforeEach(() => {
            testContext.password = 'Qwer1234!';
        });
        test('should throw an InvalidArgumentError, if keypair is falsy', () => {
            expect(() => Crypto.encryptPrivateKey(null, testContext.password)).toThrow(InvalidArgumentError);
        });
        test('should throw an InvalidKeyPairError, if versions of keys dont match', () => {
            testContext.plainUserKeyPairContainer = {
                privateKeyContainer: plainPrivateKey2048 as PrivateKeyContainer,
                publicKeyContainer: publicKey4096 as PublicKeyContainer
            };

            expect(() => Crypto.encryptPrivateKey(testContext.plainUserKeyPairContainer, testContext.password)).toThrow(
                InvalidKeyPairError
            );
        });
        test('should throw an InvalidKeyPairError, if version is not supported', () => {
            testContext.plainUserKeyPairContainer = {
                privateKeyContainer: plainPrivateKeyBadVersion as PrivateKeyContainer,
                publicKeyContainer: publicKeyBadVersion as PublicKeyContainer
            };

            expect(() => Crypto.encryptPrivateKey(testContext.plainUserKeyPairContainer, testContext.password)).toThrow(
                InvalidKeyPairError
            );
        });
        test('should throw an EncryptionError, if keys are not in valid PEM format', () => {
            testContext.plainUserKeyPairContainer = {
                privateKeyContainer: plainPrivateKeyBadPem as PrivateKeyContainer,
                publicKeyContainer: publicKeyBadPem as PublicKeyContainer
            };

            expect(() => Crypto.encryptPrivateKey(testContext.plainUserKeyPairContainer, testContext.password)).toThrow(EncryptionError);
        });
        test('should throw an EncryptionError, if keys are not in valid ASN.1 format', () => {
            testContext.plainUserKeyPairContainer = {
                privateKeyContainer: plainPrivateKeyBadAsn1 as PrivateKeyContainer,
                publicKeyContainer: publicKeyBadAsn1 as PublicKeyContainer
            };

            expect(() => Crypto.encryptPrivateKey(testContext.plainUserKeyPairContainer, testContext.password)).toThrow(EncryptionError);
        });
    });
    describe('with invalid password', () => {
        beforeEach(() => {
            testContext.plainUserKeyPairContainer = {
                privateKeyContainer: plainPrivateKey2048 as PrivateKeyContainer,
                publicKeyContainer: publicKey2048 as PublicKeyContainer
            };
        });
        test('should throw an InvalidArgumentError, if password is falsy', () => {
            expect(() => Crypto.encryptPrivateKey(testContext.plainUserKeyPairContainer, null)).toThrow(InvalidArgumentError);
        });
        test('should throw an InvalidArgumentError, if password is empty string', () => {
            expect(() => Crypto.encryptPrivateKey(testContext.plainUserKeyPairContainer, '')).toThrow(InvalidArgumentError);
        });
    });
});
