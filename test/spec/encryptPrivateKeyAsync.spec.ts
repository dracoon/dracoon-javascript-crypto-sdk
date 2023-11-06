import { Crypto } from '../../src/Crypto.node';
import { UserKeyPairVersion } from '../../src/enums/UserKeyPairVersion';
import { encryptRsaPrivateKeyAsync } from '../../src/internal/privateKeyAsync/encryptPrivateKeyAsync';
import { getCryptoWorker } from '../../src/internal/cryptoWorker';
import { SupportedCipherType, SupportedHashAlgorithm, ValidKeyLength } from '../../src/internal/privateKeyAsync/models';
import { PrivateKeyContainer } from '../../src/models/PrivateKeyContainer';
import { PublicKeyContainer } from '../../src/models/PublicKeyContainer';
import { UserKeyPairContainer } from '../../src/models/UserKeyPairContainer';
import plainPrivateKey2048 from '../keys/javascript/kp_rsa2048/plain_private_key.json';
import publicKey2048 from '../keys/javascript/kp_rsa2048/public_key.json';
import keypair_4096_2 from '../keys/javascript/kp_rsa4096_2/kp_rsa4096_2.json';

describe('Function: Crypto.encryptPrivateKeyAsync', () => {
    it('should produce exactly the same output as non async', async () => {
        const { algorithm, count, iv, keyLength, password, prfAlgorithm, salt } = keypair_4096_2.config;

        const encrypted = await encryptRsaPrivateKeyAsync(
            keypair_4096_2.plainUserKeyPairContainer.privateKeyContainer.privateKey,
            password,
            {
                hashingParams: {
                    iterationCount: count,
                    hmacHashAlgorithm: prfAlgorithm as SupportedHashAlgorithm,
                    salt: new Uint8Array(salt)
                },
                encryptParams: { iv: new Uint8Array(iv), length: keyLength as ValidKeyLength, name: algorithm as SupportedCipherType }
            },
            getCryptoWorker()
        );

        expect(encrypted).toEqual(keypair_4096_2.encryptedUserKeyPairContainer.privateKeyContainer.privateKey);
    });

    describe('UserKeyPairContainer handling', () => {
        describe('with keypair version RSA-2048 (A)', () => {
            let testContext: { userKeyPairContainer: UserKeyPairContainer; password: string };
            beforeEach(() => {
                testContext = {
                    userKeyPairContainer: {
                        privateKeyContainer: plainPrivateKey2048 as PrivateKeyContainer,
                        publicKeyContainer: publicKey2048 as PublicKeyContainer
                    },
                    password: 'Qwer1234!'
                };
            });
            test('should return a UserKeyPairContainer with the correct properties', async () => {
                const userKeyPairContainer: UserKeyPairContainer = await Crypto.encryptPrivateKeyAsync(
                    testContext.userKeyPairContainer,
                    testContext.password
                );

                expect(Object.keys(userKeyPairContainer)).toContain('privateKeyContainer');
                expect(Object.keys(userKeyPairContainer)).toContain('publicKeyContainer');
                expect(Object.keys(userKeyPairContainer.privateKeyContainer)).toContain('version');
                expect(Object.keys(userKeyPairContainer.privateKeyContainer)).toContain('privateKey');
                expect(Object.keys(userKeyPairContainer.publicKeyContainer)).toContain('version');
                expect(Object.keys(userKeyPairContainer.publicKeyContainer)).toContain('publicKey');
            });
            test('should return a UserKeyPairContainer with the correct crypto version', async () => {
                const userKeyPairContainer: UserKeyPairContainer = await Crypto.encryptPrivateKeyAsync(
                    testContext.userKeyPairContainer,
                    testContext.password
                );

                expect(userKeyPairContainer.privateKeyContainer.version).toBe(UserKeyPairVersion.RSA2048);
                expect(userKeyPairContainer.publicKeyContainer.version).toBe(UserKeyPairVersion.RSA2048);
            });
            test('should return a UserKeyPairContainer with keys in PEM format', async () => {
                const userKeyPairContainer: UserKeyPairContainer = await Crypto.encryptPrivateKeyAsync(
                    testContext.userKeyPairContainer,
                    testContext.password
                );

                expect(userKeyPairContainer.privateKeyContainer.privateKey).toContain('-----BEGIN ENCRYPTED PRIVATE KEY-----');
                expect(userKeyPairContainer.privateKeyContainer.privateKey).toContain('-----END ENCRYPTED PRIVATE KEY-----');
                expect(userKeyPairContainer.publicKeyContainer.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
                expect(userKeyPairContainer.publicKeyContainer.publicKey).toContain('-----END PUBLIC KEY-----');
            });
            test('should return a UserKeyPairContainer with identical public key', async () => {
                const userKeyPairContainer: UserKeyPairContainer = await Crypto.encryptPrivateKeyAsync(
                    testContext.userKeyPairContainer,
                    testContext.password
                );

                expect(userKeyPairContainer.publicKeyContainer.publicKey).toBe(
                    testContext.userKeyPairContainer.publicKeyContainer.publicKey
                );
            });
        });
        describe('with keypair version RSA-4096', () => {
            test('should return a UserKeyPairContainer with the correct properties', async () => {
                const userKeyPairContainer: UserKeyPairContainer = await Crypto.encryptPrivateKeyAsync(
                    keypair_4096_2.plainUserKeyPairContainer as UserKeyPairContainer,
                    keypair_4096_2.config.password
                );

                expect(Object.keys(userKeyPairContainer)).toContain('privateKeyContainer');
                expect(Object.keys(userKeyPairContainer)).toContain('publicKeyContainer');
                expect(Object.keys(userKeyPairContainer.privateKeyContainer)).toContain('version');
                expect(Object.keys(userKeyPairContainer.privateKeyContainer)).toContain('privateKey');
                expect(Object.keys(userKeyPairContainer.publicKeyContainer)).toContain('version');
                expect(Object.keys(userKeyPairContainer.publicKeyContainer)).toContain('publicKey');
            });
            test('should return a UserKeyPairContainer with the correct crypto version', async () => {
                const userKeyPairContainer: UserKeyPairContainer = await Crypto.encryptPrivateKeyAsync(
                    keypair_4096_2.plainUserKeyPairContainer as UserKeyPairContainer,
                    keypair_4096_2.config.password
                );

                expect(userKeyPairContainer.privateKeyContainer.version).toBe(UserKeyPairVersion.RSA4096);
                expect(userKeyPairContainer.publicKeyContainer.version).toBe(UserKeyPairVersion.RSA4096);
            });
            test('should return a UserKeyPairContainer with keys in PEM format', async () => {
                const userKeyPairContainer: UserKeyPairContainer = await Crypto.encryptPrivateKeyAsync(
                    keypair_4096_2.plainUserKeyPairContainer as UserKeyPairContainer,
                    keypair_4096_2.config.password
                );

                expect(userKeyPairContainer.privateKeyContainer.privateKey).toContain('-----BEGIN ENCRYPTED PRIVATE KEY-----');
                expect(userKeyPairContainer.privateKeyContainer.privateKey).toContain('-----END ENCRYPTED PRIVATE KEY-----');
                expect(userKeyPairContainer.publicKeyContainer.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
                expect(userKeyPairContainer.publicKeyContainer.publicKey).toContain('-----END PUBLIC KEY-----');
            });
            test('should return a UserKeyPairContainer with identical public key', async () => {
                const userKeyPairContainer: UserKeyPairContainer = await Crypto.encryptPrivateKeyAsync(
                    keypair_4096_2.plainUserKeyPairContainer as UserKeyPairContainer,
                    keypair_4096_2.config.password
                );

                expect(userKeyPairContainer.publicKeyContainer.publicKey).toBe(
                    keypair_4096_2.plainUserKeyPairContainer.publicKeyContainer.publicKey
                );
            });
        });
    });
});
