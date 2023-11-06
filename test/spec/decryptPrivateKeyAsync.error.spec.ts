import { Crypto } from '../../src/index.node';
import { DecryptionError } from '../../src/error/models/DecryptionError';
import { InvalidArgumentError } from '../../src/error/models/InvalidArgumentError';
import { InvalidKeyPairError } from '../../src/error/models/InvalidKeyPairError';
import { PrivateKeyContainer } from '../../src/models/PrivateKeyContainer';
import { PublicKeyContainer } from '../../src/models/PublicKeyContainer';
import { UserKeyPairContainer } from '../../src/models/UserKeyPairContainer';

// Javascript crypto sdk keys
import privateKey2048 from '../keys/javascript/kp_rsa2048/private_key.json';
import publicKey2048 from '../keys/javascript/kp_rsa2048/public_key.json';
import publicKey4096 from '../keys/javascript/kp_rsa4096/public_key.json';

// Javascript crypto sdk keys (corrupted)
import privateKeyBadAsn1 from '../keys/corrupted/private_key_bad_asn1.json';
import privateKeyBadKey from '../keys/corrupted/private_key_bad_key.json';
import privateKeyBadPem from '../keys/corrupted/private_key_bad_pem.json';
import privateKeyBadVersion from '../keys/corrupted/private_key_bad_version.json';
import publicKeyBadAsn1 from '../keys/corrupted/public_key_bad_asn1.json';
import publicKeyBadPem from '../keys/corrupted/public_key_bad_pem.json';
import publicKeyBadVersion from '../keys/corrupted/public_key_bad_version.json';

type Context = {
    userKeyPairContainer: UserKeyPairContainer;
    password: string;
};

describe('Function: Crypto.decryptPrivateKeyAsync', () => {
    let testContext: Context;

    beforeEach(() => {
        testContext = {} as Context;
    });

    describe('with invalid keypair', () => {
        beforeEach(() => {
            testContext.password = 'Qwer1234!';
        });
        test('should throw an InvalidArgumentError, if keypair is falsy', () => {
            expect(() => Crypto.decryptPrivateKeyAsync(null, testContext.password)).rejects.toThrow(InvalidArgumentError);
        });
        test('should throw an InvalidKeyPairError, if versions of keys dont match', () => {
            testContext.userKeyPairContainer = {
                privateKeyContainer: privateKey2048 as PrivateKeyContainer,
                publicKeyContainer: publicKey4096 as PublicKeyContainer
            };

            expect(() => Crypto.decryptPrivateKeyAsync(testContext.userKeyPairContainer, testContext.password)).rejects.toThrow(
                InvalidKeyPairError
            );
        });
        test('should throw an InvalidKeyPairError, if version is not supported', () => {
            testContext.userKeyPairContainer = {
                privateKeyContainer: privateKeyBadVersion as PrivateKeyContainer,
                publicKeyContainer: publicKeyBadVersion as PublicKeyContainer
            };

            expect(() => Crypto.decryptPrivateKeyAsync(testContext.userKeyPairContainer, testContext.password)).rejects.toThrow(
                InvalidKeyPairError
            );
        });
        test('should throw a DecryptionError, if keys are not in valid PEM format', () => {
            testContext.userKeyPairContainer = {
                privateKeyContainer: privateKeyBadPem as PrivateKeyContainer,
                publicKeyContainer: publicKeyBadPem as PublicKeyContainer
            };

            expect(() => Crypto.decryptPrivateKeyAsync(testContext.userKeyPairContainer, testContext.password)).rejects.toThrow(
                DecryptionError
            );
        });
        test('should throw a DecryptionError, if keys are not in valid ASN.1 format', () => {
            testContext.userKeyPairContainer = {
                privateKeyContainer: privateKeyBadAsn1 as PrivateKeyContainer,
                publicKeyContainer: publicKeyBadAsn1 as PublicKeyContainer
            };

            expect(() => Crypto.decryptPrivateKeyAsync(testContext.userKeyPairContainer, testContext.password)).rejects.toThrow(
                DecryptionError
            );
        });
        test('should throw a DecryptionError, if private key has been modified', () => {
            testContext.userKeyPairContainer = {
                privateKeyContainer: privateKeyBadKey as PrivateKeyContainer,
                publicKeyContainer: publicKey2048 as PublicKeyContainer
            };

            expect(() => Crypto.decryptPrivateKeyAsync(testContext.userKeyPairContainer, testContext.password)).rejects.toThrow(
                DecryptionError
            );
        });
    });
    describe('with invalid password', () => {
        beforeEach(() => {
            testContext.userKeyPairContainer = {
                privateKeyContainer: privateKey2048 as PrivateKeyContainer,
                publicKeyContainer: publicKey2048 as PublicKeyContainer
            };
        });
        test('should throw an InvalidArgumentError, if password is falsy', () => {
            expect(() => Crypto.decryptPrivateKeyAsync(testContext.userKeyPairContainer, null)).rejects.toThrow(InvalidArgumentError);
        });
        test('should throw an InvalidArgumentError, if password is empty string', () => {
            expect(() => Crypto.decryptPrivateKeyAsync(testContext.userKeyPairContainer, '')).rejects.toThrow(InvalidArgumentError);
        });
        test('should throw a DecryptionError, if password is not correct', () => {
            expect(() => Crypto.decryptPrivateKeyAsync(testContext.userKeyPairContainer, 'wrongPassword')).rejects.toThrow(DecryptionError);
        });
    });
});
