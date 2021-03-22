import forge from 'node-forge';
import { Crypto } from '../../src/index';
import { UserKeyPairVersion } from '../../src/enums/UserKeyPairVersion';
import { UserKeyPairContainer } from '../../src/models/UserKeyPairContainer';

type Context = {
    version: UserKeyPairVersion;
    password: string;
};

describe('Function: Crypto.generateUserKeyPair', () => {
    let testContext: Context;

    beforeEach(() => {
        testContext = {} as Context;
    });

    describe('with keypair version RSA-2048 (A)', () => {
        beforeEach(() => {
            testContext.version = UserKeyPairVersion.RSA2048;
            testContext.password = 'someRandomPassword';
        });
        test('should return a UserKeyPairContainer with the correct properties', async () => {
            const userKeyPairContainer: UserKeyPairContainer = await Crypto.generateUserKeyPair(testContext.version, testContext.password);

            expect(Object.keys(userKeyPairContainer)).toContain('privateKeyContainer');
            expect(Object.keys(userKeyPairContainer)).toContain('publicKeyContainer');
            expect(Object.keys(userKeyPairContainer.privateKeyContainer)).toContain('version');
            expect(Object.keys(userKeyPairContainer.privateKeyContainer)).toContain('privateKey');
            expect(Object.keys(userKeyPairContainer.publicKeyContainer)).toContain('version');
            expect(Object.keys(userKeyPairContainer.publicKeyContainer)).toContain('publicKey');
        });
        test('should return a UserKeyPairContainer with the correct crypto version', async () => {
            const userKeyPairContainer: UserKeyPairContainer = await Crypto.generateUserKeyPair(testContext.version, testContext.password);

            expect(userKeyPairContainer.privateKeyContainer.version).toBe(UserKeyPairVersion.RSA2048);
            expect(userKeyPairContainer.publicKeyContainer.version).toBe(UserKeyPairVersion.RSA2048);
        });
        test('should return a UserKeyPairContainer with keys in PEM format', async () => {
            const userKeyPairContainer: UserKeyPairContainer = await Crypto.generateUserKeyPair(testContext.version, testContext.password);

            expect(userKeyPairContainer.privateKeyContainer.privateKey).toContain('-----BEGIN ENCRYPTED PRIVATE KEY-----');
            expect(userKeyPairContainer.privateKeyContainer.privateKey).toContain('-----END ENCRYPTED PRIVATE KEY-----');
            expect(userKeyPairContainer.publicKeyContainer.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
            expect(userKeyPairContainer.publicKeyContainer.publicKey).toContain('-----END PUBLIC KEY-----');
        });
        test('should return a UserKeyPairContainer with a public key with a modulus of 2048 bit', async () => {
            const userKeyPairContainer: UserKeyPairContainer = await Crypto.generateUserKeyPair(testContext.version, testContext.password);

            const publicKeyPEM: forge.pki.PEM = userKeyPairContainer.publicKeyContainer.publicKey;
            const publicKey: forge.pki.PublicKey = forge.pki.publicKeyFromPem(publicKeyPEM);
            const publicKeyModulus = publicKey.n as any;
            const publicKeyModulusBitLength = publicKeyModulus.bitLength() as number;

            expect(publicKeyModulusBitLength).toBe(2048);
        });
    });
    describe('with keypair version RSA-4096', () => {
        beforeEach(() => {
            testContext.version = UserKeyPairVersion.RSA4096;
            testContext.password = 'someRandomPassword';
        });
        test('should return a UserKeyPairContainer with the correct properties', async () => {
            const userKeyPairContainer: UserKeyPairContainer = await Crypto.generateUserKeyPair(testContext.version, testContext.password);

            expect(Object.keys(userKeyPairContainer)).toContain('privateKeyContainer');
            expect(Object.keys(userKeyPairContainer)).toContain('publicKeyContainer');
            expect(Object.keys(userKeyPairContainer.privateKeyContainer)).toContain('version');
            expect(Object.keys(userKeyPairContainer.privateKeyContainer)).toContain('privateKey');
            expect(Object.keys(userKeyPairContainer.publicKeyContainer)).toContain('version');
            expect(Object.keys(userKeyPairContainer.publicKeyContainer)).toContain('publicKey');
        });
        test('should return a UserKeyPairContainer with the correct crypto version', async () => {
            const userKeyPairContainer: UserKeyPairContainer = await Crypto.generateUserKeyPair(testContext.version, testContext.password);

            expect(userKeyPairContainer.privateKeyContainer.version).toBe(UserKeyPairVersion.RSA4096);
            expect(userKeyPairContainer.publicKeyContainer.version).toBe(UserKeyPairVersion.RSA4096);
        });
        test('should return a UserKeyPairContainer with keys in PEM format', async () => {
            const userKeyPairContainer: UserKeyPairContainer = await Crypto.generateUserKeyPair(testContext.version, testContext.password);

            expect(userKeyPairContainer.privateKeyContainer.privateKey).toContain('-----BEGIN ENCRYPTED PRIVATE KEY-----');
            expect(userKeyPairContainer.privateKeyContainer.privateKey).toContain('-----END ENCRYPTED PRIVATE KEY-----');
            expect(userKeyPairContainer.publicKeyContainer.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
            expect(userKeyPairContainer.publicKeyContainer.publicKey).toContain('-----END PUBLIC KEY-----');
        });
        test('should return a UserKeyPairContainer with a public key with a modulus of 4096 bit', async () => {
            const userKeyPairContainer: UserKeyPairContainer = await Crypto.generateUserKeyPair(testContext.version, testContext.password);

            const publicKeyPEM: forge.pki.PEM = userKeyPairContainer.publicKeyContainer.publicKey;
            const publicKey: forge.pki.PublicKey = forge.pki.publicKeyFromPem(publicKeyPEM);
            const publicKeyModulus = publicKey.n as any;
            const publicKeyModulusBitLength = publicKeyModulus.bitLength() as number;

            expect(publicKeyModulusBitLength).toBe(4096);
        });
    });
});
