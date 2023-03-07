import { Crypto } from '../../src/index';
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

describe('Function: Crypto.decryptPrivateKey', () => {
    let testContext: Context;

    beforeEach(() => {
        testContext = {} as Context;
    });

    describe('with invalid keypair', () => {
        beforeEach(() => {
            testContext.password = 'Qwer1234!';
        });

        test('should throw an InvalidArgumentError, if keypair is falsy', () => {
            expect(() => Crypto.decryptPrivateKey(null as unknown as UserKeyPairContainer, testContext.password)).toThrow(InvalidArgumentError);
        });
        test('should throw an InvalidArgumentError, if key is falsy', () => {
            expect(() => Crypto.decryptPrivateKeyOnly(null as unknown as PrivateKeyContainer, testContext.password)).toThrow(InvalidArgumentError);
        });
        test('should throw an InvalidKeyPairError, if versions of keys dont match', () => {
            testContext.userKeyPairContainer = {
                privateKeyContainer: privateKey2048 as PrivateKeyContainer,
                publicKeyContainer: publicKey4096 as PublicKeyContainer
            };

            expect(() => Crypto.decryptPrivateKey(testContext.userKeyPairContainer, testContext.password)).toThrow(InvalidKeyPairError);
            
        });

        test('should throw an InvalidKeyPairError, if version is not supported', () => {
            testContext.userKeyPairContainer = {
                privateKeyContainer: privateKeyBadVersion as PrivateKeyContainer,
                publicKeyContainer: publicKeyBadVersion as PublicKeyContainer
            };

            expect(() => Crypto.decryptPrivateKey(testContext.userKeyPairContainer, testContext.password)).toThrow(InvalidKeyPairError);
            expect(() => Crypto.decryptPrivateKeyOnly(testContext.userKeyPairContainer.privateKeyContainer, testContext.password)).toThrow(InvalidKeyPairError);
        });
        test('should throw a DecryptionError, if keys are not in valid PEM format', () => {
            testContext.userKeyPairContainer = {
                privateKeyContainer: privateKeyBadPem as PrivateKeyContainer,
                publicKeyContainer: publicKeyBadPem as PublicKeyContainer
            };

            expect(() => Crypto.decryptPrivateKey(testContext.userKeyPairContainer, testContext.password)).toThrow(DecryptionError);
            expect(() => Crypto.decryptPrivateKeyOnly(testContext.userKeyPairContainer.privateKeyContainer, testContext.password)).toThrow(DecryptionError);
        });
        test('should throw a DecryptionError, if keys are not in valid ASN.1 format', () => {
            testContext.userKeyPairContainer = {
                privateKeyContainer: privateKeyBadAsn1 as PrivateKeyContainer,
                publicKeyContainer: publicKeyBadAsn1 as PublicKeyContainer
            };

            expect(() => Crypto.decryptPrivateKey(testContext.userKeyPairContainer, testContext.password)).toThrow(DecryptionError);
            expect(() => Crypto.decryptPrivateKeyOnly(testContext.userKeyPairContainer.privateKeyContainer, testContext.password)).toThrow(DecryptionError);
        });
        test('should throw a DecryptionError, if private key has been modified', () => {
            testContext.userKeyPairContainer = {
                privateKeyContainer: privateKeyBadKey as PrivateKeyContainer,
                publicKeyContainer: publicKey2048 as PublicKeyContainer
            };

            expect(() => Crypto.decryptPrivateKey(testContext.userKeyPairContainer, testContext.password)).toThrow(DecryptionError);
            expect(() => Crypto.decryptPrivateKeyOnly(testContext.userKeyPairContainer.privateKeyContainer, testContext.password)).toThrow(DecryptionError);
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
            expect(() => Crypto.decryptPrivateKey(testContext.userKeyPairContainer, null as unknown as string)).toThrow(InvalidArgumentError);
            expect(() => Crypto.decryptPrivateKeyOnly(testContext.userKeyPairContainer.privateKeyContainer, null as unknown as string)).toThrow(InvalidArgumentError);
        });
        test('should throw an InvalidArgumentError, if password is empty string', () => {
            expect(() => Crypto.decryptPrivateKey(testContext.userKeyPairContainer, '')).toThrow(InvalidArgumentError);
            expect(() => Crypto.decryptPrivateKeyOnly(testContext.userKeyPairContainer.privateKeyContainer, '')).toThrow(InvalidArgumentError);
        });
        test('should throw a DecryptionError, if password is not correct', () => {
            expect(() => Crypto.decryptPrivateKey(testContext.userKeyPairContainer, 'wrongPassword')).toThrow(DecryptionError);
            expect(() => Crypto.decryptPrivateKeyOnly(testContext.userKeyPairContainer.privateKeyContainer, 'wrongPassword')).toThrow(DecryptionError);
        });
    });
});
