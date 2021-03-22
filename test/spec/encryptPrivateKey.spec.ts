import { Crypto } from '../../src/index';
import { UserKeyPairVersion } from '../../src/enums/UserKeyPairVersion';
import { PlainUserKeyPairContainer } from '../../src/models/PlainUserKeyPairContainer';
import { PrivateKeyContainer } from '../../src/models/PrivateKeyContainer';
import { PublicKeyContainer } from '../../src/models/PublicKeyContainer';
import { UserKeyPairContainer } from '../../src/models/UserKeyPairContainer';

// Javascript crypto sdk keys
import plainPrivateKey2048 from '../keys/javascript/kp_rsa2048/plain_private_key.json';
import publicKey2048 from '../keys/javascript/kp_rsa2048/public_key.json';
import plainPrivateKey4096 from '../keys/javascript/kp_rsa4096/plain_private_key.json';
import publicKey4096 from '../keys/javascript/kp_rsa4096/public_key.json';

type Context = {
    plainUserKeyPairContainer: PlainUserKeyPairContainer;
    password: string;
};

describe('Function: Crypto.encryptPrivateKey', () => {
    let testContext: Context;

    beforeEach(() => {
        testContext = {} as Context;
    });

    describe('with keypair version RSA-2048 (A)', () => {
        beforeEach(() => {
            testContext.plainUserKeyPairContainer = {
                privateKeyContainer: plainPrivateKey2048 as PrivateKeyContainer,
                publicKeyContainer: publicKey2048 as PublicKeyContainer
            };
            testContext.password = 'Qwer1234!';
        });
        test('should return a UserKeyPairContainer with the correct properties', () => {
            const userKeyPairContainer: UserKeyPairContainer = Crypto.encryptPrivateKey(
                testContext.plainUserKeyPairContainer,
                testContext.password
            );

            expect(Object.keys(userKeyPairContainer)).toContain('privateKeyContainer');
            expect(Object.keys(userKeyPairContainer)).toContain('publicKeyContainer');
            expect(Object.keys(userKeyPairContainer.privateKeyContainer)).toContain('version');
            expect(Object.keys(userKeyPairContainer.privateKeyContainer)).toContain('privateKey');
            expect(Object.keys(userKeyPairContainer.publicKeyContainer)).toContain('version');
            expect(Object.keys(userKeyPairContainer.publicKeyContainer)).toContain('publicKey');
        });
        test('should return a UserKeyPairContainer with the correct crypto version', () => {
            const userKeyPairContainer: UserKeyPairContainer = Crypto.encryptPrivateKey(
                testContext.plainUserKeyPairContainer,
                testContext.password
            );

            expect(userKeyPairContainer.privateKeyContainer.version).toBe(UserKeyPairVersion.RSA2048);
            expect(userKeyPairContainer.publicKeyContainer.version).toBe(UserKeyPairVersion.RSA2048);
        });
        test('should return a UserKeyPairContainer with keys in PEM format', () => {
            const userKeyPairContainer: UserKeyPairContainer = Crypto.encryptPrivateKey(
                testContext.plainUserKeyPairContainer,
                testContext.password
            );

            expect(userKeyPairContainer.privateKeyContainer.privateKey).toContain('-----BEGIN ENCRYPTED PRIVATE KEY-----');
            expect(userKeyPairContainer.privateKeyContainer.privateKey).toContain('-----END ENCRYPTED PRIVATE KEY-----');
            expect(userKeyPairContainer.publicKeyContainer.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
            expect(userKeyPairContainer.publicKeyContainer.publicKey).toContain('-----END PUBLIC KEY-----');
        });
        test('should return a UserKeyPairContainer with identical public key', () => {
            const userKeyPairContainer: UserKeyPairContainer = Crypto.encryptPrivateKey(
                testContext.plainUserKeyPairContainer,
                testContext.password
            );

            expect(userKeyPairContainer.publicKeyContainer.publicKey).toBe(
                testContext.plainUserKeyPairContainer.publicKeyContainer.publicKey
            );
        });
    });
    describe('with keypair version RSA-4096', () => {
        beforeEach(() => {
            testContext.plainUserKeyPairContainer = {
                privateKeyContainer: plainPrivateKey4096 as PrivateKeyContainer,
                publicKeyContainer: publicKey4096 as PublicKeyContainer
            };
            testContext.password = 'Qwer1234!';
        });
        test('should return a UserKeyPairContainer with the correct properties', () => {
            const userKeyPairContainer: UserKeyPairContainer = Crypto.encryptPrivateKey(
                testContext.plainUserKeyPairContainer,
                testContext.password
            );

            expect(Object.keys(userKeyPairContainer)).toContain('privateKeyContainer');
            expect(Object.keys(userKeyPairContainer)).toContain('publicKeyContainer');
            expect(Object.keys(userKeyPairContainer.privateKeyContainer)).toContain('version');
            expect(Object.keys(userKeyPairContainer.privateKeyContainer)).toContain('privateKey');
            expect(Object.keys(userKeyPairContainer.publicKeyContainer)).toContain('version');
            expect(Object.keys(userKeyPairContainer.publicKeyContainer)).toContain('publicKey');
        });
        test('should return a UserKeyPairContainer with the correct crypto version', () => {
            const userKeyPairContainer: UserKeyPairContainer = Crypto.encryptPrivateKey(
                testContext.plainUserKeyPairContainer,
                testContext.password
            );

            expect(userKeyPairContainer.privateKeyContainer.version).toBe(UserKeyPairVersion.RSA4096);
            expect(userKeyPairContainer.publicKeyContainer.version).toBe(UserKeyPairVersion.RSA4096);
        });
        test('should return a UserKeyPairContainer with keys in PEM format', () => {
            const userKeyPairContainer: UserKeyPairContainer = Crypto.encryptPrivateKey(
                testContext.plainUserKeyPairContainer,
                testContext.password
            );

            expect(userKeyPairContainer.privateKeyContainer.privateKey).toContain('-----BEGIN ENCRYPTED PRIVATE KEY-----');
            expect(userKeyPairContainer.privateKeyContainer.privateKey).toContain('-----END ENCRYPTED PRIVATE KEY-----');
            expect(userKeyPairContainer.publicKeyContainer.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
            expect(userKeyPairContainer.publicKeyContainer.publicKey).toContain('-----END PUBLIC KEY-----');
        });
        test('should return a UserKeyPairContainer with identical public key', () => {
            const userKeyPairContainer: UserKeyPairContainer = Crypto.encryptPrivateKey(
                testContext.plainUserKeyPairContainer,
                testContext.password
            );

            expect(userKeyPairContainer.publicKeyContainer.publicKey).toBe(
                testContext.plainUserKeyPairContainer.publicKeyContainer.publicKey
            );
        });
    });
});
