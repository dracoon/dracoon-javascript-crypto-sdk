import { Crypto } from '../../src/Crypto.node';
import { UserKeyPairVersion } from '../../src/enums/UserKeyPairVersion';
import { PlainUserKeyPairContainer } from '../../src/models/PlainUserKeyPairContainer';
import { UserKeyPairContainer } from '../../src/models/UserKeyPairContainer';
import keypair_4096_2 from '../keys/javascript/kp_rsa4096_2/kp_rsa4096_2.json';

import { PrivateKeyContainer } from '../../src/models/PrivateKeyContainer';
import { PublicKeyContainer } from '../../src/models/PublicKeyContainer';
import plainPrivateKey2048 from '../keys/javascript/kp_rsa2048/plain_private_key.json';
import privateKey2048 from '../keys/javascript/kp_rsa2048/private_key.json';
import publicKey2048 from '../keys/javascript/kp_rsa2048/public_key.json';

describe('Function: Crypto.decryptPrivateKeyAsync', () => {
    describe('with keypair version RSA-2048 (A)', () => {
        let testContext: { userKeyPairContainer: UserKeyPairContainer; password: string };
        beforeEach(() => {
            testContext = {
                userKeyPairContainer: {
                    privateKeyContainer: privateKey2048 as PrivateKeyContainer,
                    publicKeyContainer: publicKey2048 as PublicKeyContainer
                },
                password: 'Qwer1234!'
            };
        });
        test('should return a PlainUserKeyPairContainer with the correct properties', async () => {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = await Crypto.decryptPrivateKeyAsync(
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
        test('should return a PlainUserKeyPairContainer with the correct crypto version', async () => {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = await Crypto.decryptPrivateKeyAsync(
                testContext.userKeyPairContainer,
                testContext.password
            );

            expect(plainUserKeyPairContainer.privateKeyContainer.version).toBe(UserKeyPairVersion.RSA2048);
            expect(plainUserKeyPairContainer.publicKeyContainer.version).toBe(UserKeyPairVersion.RSA2048);
        });
        test('should return a PlainUserKeyPairContainer with keys in PEM format', async () => {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = await Crypto.decryptPrivateKeyAsync(
                testContext.userKeyPairContainer,
                testContext.password
            );

            expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----BEGIN RSA PRIVATE KEY-----');
            expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----END RSA PRIVATE KEY-----');
            expect(plainUserKeyPairContainer.publicKeyContainer.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
            expect(plainUserKeyPairContainer.publicKeyContainer.publicKey).toContain('-----END PUBLIC KEY-----');
        });
        test('should return a PlainUserKeyPairContainer with identical public key', async () => {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = await Crypto.decryptPrivateKeyAsync(
                testContext.userKeyPairContainer,
                testContext.password
            );

            expect(plainUserKeyPairContainer.publicKeyContainer.publicKey).toBe(
                testContext.userKeyPairContainer.publicKeyContainer.publicKey
            );
        });
        test('should return a PlainUserKeyPairContainer with the correct plain private key', async () => {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = await Crypto.decryptPrivateKeyAsync(
                testContext.userKeyPairContainer,
                testContext.password
            );

            expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toBe(plainPrivateKey2048.privateKey);
        });
    });

    describe('with keypair version RSA-4096', () => {
        test('should return a PlainUserKeyPairContainer with the correct properties', async () => {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = await Crypto.decryptPrivateKeyAsync(
                keypair_4096_2.encryptedUserKeyPairContainer as UserKeyPairContainer,
                keypair_4096_2.config.password
            );

            expect(Object.keys(plainUserKeyPairContainer)).toContain('privateKeyContainer');
            expect(Object.keys(plainUserKeyPairContainer)).toContain('publicKeyContainer');
            expect(Object.keys(plainUserKeyPairContainer.privateKeyContainer)).toContain('version');
            expect(Object.keys(plainUserKeyPairContainer.privateKeyContainer)).toContain('privateKey');
            expect(Object.keys(plainUserKeyPairContainer.publicKeyContainer)).toContain('version');
            expect(Object.keys(plainUserKeyPairContainer.publicKeyContainer)).toContain('publicKey');
        });
        test('should return a PlainUserKeyPairContainer with the correct crypto version', async () => {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = await Crypto.decryptPrivateKeyAsync(
                keypair_4096_2.encryptedUserKeyPairContainer as UserKeyPairContainer,
                keypair_4096_2.config.password
            );

            expect(plainUserKeyPairContainer.privateKeyContainer.version).toBe(UserKeyPairVersion.RSA4096);
            expect(plainUserKeyPairContainer.publicKeyContainer.version).toBe(UserKeyPairVersion.RSA4096);
        });
        test('should return a PlainUserKeyPairContainer with keys in PEM format', async () => {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = await Crypto.decryptPrivateKeyAsync(
                keypair_4096_2.encryptedUserKeyPairContainer as UserKeyPairContainer,
                keypair_4096_2.config.password
            );

            expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----BEGIN RSA PRIVATE KEY-----');
            expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----END RSA PRIVATE KEY-----');
            expect(plainUserKeyPairContainer.publicKeyContainer.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
            expect(plainUserKeyPairContainer.publicKeyContainer.publicKey).toContain('-----END PUBLIC KEY-----');
        });
        test('should return a PlainUserKeyPairContainer with identical public key', async () => {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = await Crypto.decryptPrivateKeyAsync(
                keypair_4096_2.encryptedUserKeyPairContainer as UserKeyPairContainer,
                keypair_4096_2.config.password
            );

            expect(plainUserKeyPairContainer.publicKeyContainer.publicKey).toBe(
                keypair_4096_2.encryptedUserKeyPairContainer.publicKeyContainer.publicKey
            );
        });
        test('should return a PlainUserKeyPairContainer with the correct plain private key', async () => {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = await Crypto.decryptPrivateKeyAsync(
                keypair_4096_2.encryptedUserKeyPairContainer as UserKeyPairContainer,
                keypair_4096_2.config.password
            );

            expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toBe(
                keypair_4096_2.plainUserKeyPairContainer.privateKeyContainer.privateKey
            );
        });
    });
});
