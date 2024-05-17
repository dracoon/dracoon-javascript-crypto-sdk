import { Crypto } from '../../src/index.node';
import { PrivateKeyContainer } from '../../src/models/PrivateKeyContainer';
import { PublicKeyContainer } from '../../src/models/PublicKeyContainer';
import { UserKeyPairContainer } from '../../src/models/UserKeyPairContainer';

// Javascript crypto sdk keys
import privateKey2048 from '../keys/javascript/kp_rsa2048/private_key.json';
import publicKey2048 from '../keys/javascript/kp_rsa2048/public_key.json';
import privateKey4096 from '../keys/javascript/kp_rsa4096/private_key.json';
import publicKey4096 from '../keys/javascript/kp_rsa4096/public_key.json';

//import keyPairs with Umlaute
import keypair_2048_old from '../keys/javascript/kp_rsa2048_old/kp_rsa2048_old.json';
import keypair_2048_new from '../keys/javascript/kp_rsa2048_new/kp_rsa2048_new.json';
import keypair_4096_old from '../keys/javascript/kp_rsa4096_old/kp_rsa4096_old.json';
import keypair_4096_new from '../keys/javascript/kp_rsa4096_new/kp_rsa4096_new.json';

// Javascript crypto sdk keys (corrupted)
import privateKeyBadKey from '../keys/corrupted/private_key_bad_key.json';

type Context = {
    userKeyPairContainer: UserKeyPairContainer;
    password: string;
};

describe('Function: Crypto.checkUserKeyPair', () => {
    let testContext: Context;

    beforeEach(() => {
        testContext = {} as Context;
    });

    describe('with keypair version RSA-2048 (A)', () => {
        beforeEach(() => {
            testContext.userKeyPairContainer = {
                privateKeyContainer: privateKey2048 as PrivateKeyContainer,
                publicKeyContainer: publicKey2048 as PublicKeyContainer
            };
        });
        test('should return true, if password is correct', () => {
            testContext.password = 'Qwer1234!';

            const result = Crypto.checkUserKeyPair(testContext.userKeyPairContainer, testContext.password);

            expect(result).toBe(true);
        });
        test('should return true, if password is correct even if it has umlaute', () => {
            testContext.password = 'Qwer1234!äö';
            const result = Crypto.checkUserKeyPair(
                keypair_2048_old.encryptedUserKeyPairContainer as UserKeyPairContainer,
                testContext.password
            );

            expect(result).toBe(true);
        });
        test('should return false, if password is not correct', () => {
            testContext.password = 'wrongPassword';

            const result = Crypto.checkUserKeyPair(testContext.userKeyPairContainer, testContext.password);

            expect(result).toBe(false);
        });
        test('should return false, as the used cryptolib cannot decrypt newly created Key Pairs', () => {
            testContext.password = 'Qwer1234!äö';
            const result = Crypto.checkUserKeyPair(
                keypair_2048_new.encryptedUserKeyPairContainer as UserKeyPairContainer,
                testContext.password
            );

            expect(result).toBe(false);
        });
    });
    describe('with keypair version RSA-4096', () => {
        beforeEach(() => {
            testContext.userKeyPairContainer = {
                privateKeyContainer: privateKey4096 as PrivateKeyContainer,
                publicKeyContainer: publicKey4096 as PublicKeyContainer
            };
        });
        test('should return true, if password is correct', () => {
            testContext.password = 'Qwer1234!';

            const result = Crypto.checkUserKeyPair(testContext.userKeyPairContainer, testContext.password);

            expect(result).toBe(true);
        });
        test('should return true, if password is correct even if it has umlaute', () => {
            testContext.password = 'Qwer1234!äö';
            const result = Crypto.checkUserKeyPair(
                keypair_4096_old.encryptedUserKeyPairContainer as UserKeyPairContainer,
                testContext.password
            );

            expect(result).toBe(true);
        });
        test('should return false, as the used cryptolib cannot decrypt newly created Key Pairs', () => {
            testContext.password = 'Qwer1234!äö';
            const result = Crypto.checkUserKeyPair(
                keypair_4096_new.encryptedUserKeyPairContainer as UserKeyPairContainer,
                testContext.password
            );

            expect(result).toBe(false);
        });
        test('should return false, if password is not correct', () => {
            testContext.password = 'wrongPassword';

            const result = Crypto.checkUserKeyPair(testContext.userKeyPairContainer, testContext.password);

            expect(result).toBe(false);
        });
    });
    describe('with modified key', () => {
        test('should return false, if private key has been modified', () => {
            testContext.userKeyPairContainer = {
                privateKeyContainer: privateKeyBadKey as PrivateKeyContainer,
                publicKeyContainer: publicKey2048 as PublicKeyContainer
            };
            testContext.password = 'Qwer1234!';

            const result = Crypto.checkUserKeyPair(testContext.userKeyPairContainer, testContext.password);

            expect(result).toBe(false);
        });
    });
});
