import { Crypto } from '../../src/index';
import { UserKeyPairVersion } from '../../src/enums/UserKeyPairVersion';
import { PlainUserKeyPairContainer } from '../../src/models/PlainUserKeyPairContainer';
import { PrivateKeyContainer } from '../../src/models/PrivateKeyContainer';
import { PublicKeyContainer } from '../../src/models/PublicKeyContainer';
import { UserKeyPairContainer } from '../../src/models/UserKeyPairContainer';

// Javascript crypto sdk keys
import plainPrivateKey2048 from '../keys/javascript/kp_rsa2048/plain_private_key.json';
import privateKey2048 from '../keys/javascript/kp_rsa2048/private_key.json';
import publicKey2048 from '../keys/javascript/kp_rsa2048/public_key.json';
import plainPrivateKey4096 from '../keys/javascript/kp_rsa4096/plain_private_key.json';
import privateKey4096 from '../keys/javascript/kp_rsa4096/private_key.json';
import publicKey4096 from '../keys/javascript/kp_rsa4096/public_key.json';

type Context = {
    userKeyPairContainer: UserKeyPairContainer;
    password: string;
};

describe('Function: Crypto.decryptPrivateKey', () => {
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
            testContext.password = 'Qwer1234!';
        });
        test('should return a PlainUserKeyPairContainer with the correct properties', () => {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(
                testContext.userKeyPairContainer,
                testContext.password
            );

            expect(Object.keys(plainUserKeyPairContainer)).toContain('privateKeyContainer');
            expect(Object.keys(plainUserKeyPairContainer)).toContain('publicKeyContainer');
            expect(Object.keys(plainUserKeyPairContainer.privateKeyContainer)).toContain('version');
            expect(Object.keys(plainUserKeyPairContainer.privateKeyContainer)).toContain('privateKey');
            expect(Object.keys(plainUserKeyPairContainer.publicKeyContainer)).toContain('version');
            expect(Object.keys(plainUserKeyPairContainer.publicKeyContainer)).toContain('publicKey');
        });
        test('should return a PlainUserKeyPairContainer with the correct crypto version', () => {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(
                testContext.userKeyPairContainer,
                testContext.password
            );

            expect(plainUserKeyPairContainer.privateKeyContainer.version).toBe(UserKeyPairVersion.RSA2048);
            expect(plainUserKeyPairContainer.publicKeyContainer.version).toBe(UserKeyPairVersion.RSA2048);
        });
        test('should return a PlainUserKeyPairContainer with keys in PEM format', () => {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(
                testContext.userKeyPairContainer,
                testContext.password
            );

            expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----BEGIN RSA PRIVATE KEY-----');
            expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----END RSA PRIVATE KEY-----');
            expect(plainUserKeyPairContainer.publicKeyContainer.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
            expect(plainUserKeyPairContainer.publicKeyContainer.publicKey).toContain('-----END PUBLIC KEY-----');
        });
        test('should return a PlainUserKeyPairContainer with identical public key', () => {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(
                testContext.userKeyPairContainer,
                testContext.password
            );

            expect(plainUserKeyPairContainer.publicKeyContainer.publicKey).toBe(
                testContext.userKeyPairContainer.publicKeyContainer.publicKey
            );
        });
        test('should return a PlainUserKeyPairContainer with the correct plain private key', () => {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(
                testContext.userKeyPairContainer,
                testContext.password
            );

            expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toBe(plainPrivateKey2048.privateKey);
        });
    });
    describe('with keypair version RSA-4096', () => {
        beforeEach(() => {
            testContext.userKeyPairContainer = {
                privateKeyContainer: privateKey4096 as PrivateKeyContainer,
                publicKeyContainer: publicKey4096 as PublicKeyContainer
            };
            testContext.password = 'Qwer1234!';
        });
        test('should return a PlainUserKeyPairContainer with the correct properties', () => {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(
                testContext.userKeyPairContainer,
                testContext.password
            );

            expect(Object.keys(plainUserKeyPairContainer)).toContain('privateKeyContainer');
            expect(Object.keys(plainUserKeyPairContainer)).toContain('publicKeyContainer');
            expect(Object.keys(plainUserKeyPairContainer.privateKeyContainer)).toContain('version');
            expect(Object.keys(plainUserKeyPairContainer.privateKeyContainer)).toContain('privateKey');
            expect(Object.keys(plainUserKeyPairContainer.publicKeyContainer)).toContain('version');
            expect(Object.keys(plainUserKeyPairContainer.publicKeyContainer)).toContain('publicKey');
        });
        test('should return a PlainUserKeyPairContainer with the correct crypto version', () => {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(
                testContext.userKeyPairContainer,
                testContext.password
            );

            expect(plainUserKeyPairContainer.privateKeyContainer.version).toBe(UserKeyPairVersion.RSA4096);
            expect(plainUserKeyPairContainer.publicKeyContainer.version).toBe(UserKeyPairVersion.RSA4096);
        });
        test('should return a PlainUserKeyPairContainer with keys in PEM format', () => {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(
                testContext.userKeyPairContainer,
                testContext.password
            );

            expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----BEGIN RSA PRIVATE KEY-----');
            expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----END RSA PRIVATE KEY-----');
            expect(plainUserKeyPairContainer.publicKeyContainer.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
            expect(plainUserKeyPairContainer.publicKeyContainer.publicKey).toContain('-----END PUBLIC KEY-----');
        });
        test('should return a PlainUserKeyPairContainer with identical public key', () => {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(
                testContext.userKeyPairContainer,
                testContext.password
            );

            expect(plainUserKeyPairContainer.publicKeyContainer.publicKey).toBe(
                testContext.userKeyPairContainer.publicKeyContainer.publicKey
            );
        });
        test('should return a PlainUserKeyPairContainer with the correct plain private key', () => {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(
                testContext.userKeyPairContainer,
                testContext.password
            );

            expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toBe(plainPrivateKey4096.privateKey);
        });
    });
});
