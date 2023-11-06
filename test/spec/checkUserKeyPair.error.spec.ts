import { Crypto } from '../../src/index.node';
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
import privateKeyBadVersion from '../keys/corrupted/private_key_bad_version.json';
import publicKeyBadVersion from '../keys/corrupted/public_key_bad_version.json';

type Context = {
    userKeyPairContainer: UserKeyPairContainer;
    password: string;
};

describe('Function: Crypto.checkUserKeyPair', () => {
    let testContext: Context;

    beforeEach(() => {
        testContext = {} as Context;
    });

    describe('with invalid keypair', () => {
        beforeEach(() => {
            testContext.password = 'Qwer1234!';
        });
        test('should throw an InvalidArgumentError, if keypair is falsy', () => {
            expect(() => Crypto.checkUserKeyPair(null, testContext.password)).toThrow(InvalidArgumentError);
        });
        test('should throw an InvalidKeyPairError, if versions of keys dont match', () => {
            testContext.userKeyPairContainer = {
                privateKeyContainer: privateKey2048 as PrivateKeyContainer,
                publicKeyContainer: publicKey4096 as PublicKeyContainer
            };

            expect(() => Crypto.checkUserKeyPair(testContext.userKeyPairContainer, testContext.password)).toThrow(InvalidKeyPairError);
        });
        test('should throw an InvalidKeyPairError, if version is not supported', () => {
            testContext.userKeyPairContainer = {
                privateKeyContainer: privateKeyBadVersion as PrivateKeyContainer,
                publicKeyContainer: publicKeyBadVersion as PublicKeyContainer
            };

            expect(() => Crypto.checkUserKeyPair(testContext.userKeyPairContainer, testContext.password)).toThrow(InvalidKeyPairError);
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
            expect(() => Crypto.checkUserKeyPair(testContext.userKeyPairContainer, null)).toThrow(InvalidArgumentError);
        });
        test('should throw an InvalidArgumentError, if password is empty string', () => {
            expect(() => Crypto.checkUserKeyPair(testContext.userKeyPairContainer, '')).toThrow(InvalidArgumentError);
        });
    });
});
