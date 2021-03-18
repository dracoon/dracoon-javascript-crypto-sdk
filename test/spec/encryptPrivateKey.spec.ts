import { Crypto } from '../../src/Crypto';
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
    describe('with keypair version RSA-2048 (A)', () => {
        beforeEach(function (this: Context) {
            this.plainUserKeyPairContainer = {
                privateKeyContainer: plainPrivateKey2048 as PrivateKeyContainer,
                publicKeyContainer: publicKey2048 as PublicKeyContainer
            };
            this.password = 'Qwer1234!';
        });
        it('should return a UserKeyPairContainer with the correct properties', function (this: Context) {
            const userKeyPairContainer: UserKeyPairContainer = Crypto.encryptPrivateKey(this.plainUserKeyPairContainer, this.password);

            expect(Object.keys(userKeyPairContainer)).toContain('privateKeyContainer');
            expect(Object.keys(userKeyPairContainer)).toContain('publicKeyContainer');
            expect(Object.keys(userKeyPairContainer.privateKeyContainer)).toContain('version');
            expect(Object.keys(userKeyPairContainer.privateKeyContainer)).toContain('privateKey');
            expect(Object.keys(userKeyPairContainer.publicKeyContainer)).toContain('version');
            expect(Object.keys(userKeyPairContainer.publicKeyContainer)).toContain('publicKey');
        });
        it('should return a UserKeyPairContainer with the correct crypto version', function (this: Context) {
            const userKeyPairContainer: UserKeyPairContainer = Crypto.encryptPrivateKey(this.plainUserKeyPairContainer, this.password);

            expect(userKeyPairContainer.privateKeyContainer.version).toEqual(UserKeyPairVersion.RSA2048);
            expect(userKeyPairContainer.publicKeyContainer.version).toEqual(UserKeyPairVersion.RSA2048);
        });
        it('should return a UserKeyPairContainer with keys in PEM format', function (this: Context) {
            const userKeyPairContainer: UserKeyPairContainer = Crypto.encryptPrivateKey(this.plainUserKeyPairContainer, this.password);

            expect(userKeyPairContainer.privateKeyContainer.privateKey).toContain('-----BEGIN ENCRYPTED PRIVATE KEY-----');
            expect(userKeyPairContainer.privateKeyContainer.privateKey).toContain('-----END ENCRYPTED PRIVATE KEY-----');
            expect(userKeyPairContainer.publicKeyContainer.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
            expect(userKeyPairContainer.publicKeyContainer.publicKey).toContain('-----END PUBLIC KEY-----');
        });
        it('should return a UserKeyPairContainer with identical public key', function (this: Context) {
            const userKeyPairContainer: UserKeyPairContainer = Crypto.encryptPrivateKey(this.plainUserKeyPairContainer, this.password);

            expect(userKeyPairContainer.publicKeyContainer.publicKey).toEqual(this.plainUserKeyPairContainer.publicKeyContainer.publicKey);
        });
    });
    describe('with keypair version RSA-4096', () => {
        beforeEach(function (this: Context) {
            this.plainUserKeyPairContainer = {
                privateKeyContainer: plainPrivateKey4096 as PrivateKeyContainer,
                publicKeyContainer: publicKey4096 as PublicKeyContainer
            };
            this.password = 'Qwer1234!';
        });
        it('should return a UserKeyPairContainer with the correct properties', function (this: Context) {
            const userKeyPairContainer: UserKeyPairContainer = Crypto.encryptPrivateKey(this.plainUserKeyPairContainer, this.password);

            expect(Object.keys(userKeyPairContainer)).toContain('privateKeyContainer');
            expect(Object.keys(userKeyPairContainer)).toContain('publicKeyContainer');
            expect(Object.keys(userKeyPairContainer.privateKeyContainer)).toContain('version');
            expect(Object.keys(userKeyPairContainer.privateKeyContainer)).toContain('privateKey');
            expect(Object.keys(userKeyPairContainer.publicKeyContainer)).toContain('version');
            expect(Object.keys(userKeyPairContainer.publicKeyContainer)).toContain('publicKey');
        });
        it('should return a UserKeyPairContainer with the correct crypto version', function (this: Context) {
            const userKeyPairContainer: UserKeyPairContainer = Crypto.encryptPrivateKey(this.plainUserKeyPairContainer, this.password);

            expect(userKeyPairContainer.privateKeyContainer.version).toEqual(UserKeyPairVersion.RSA4096);
            expect(userKeyPairContainer.publicKeyContainer.version).toEqual(UserKeyPairVersion.RSA4096);
        });
        it('should return a UserKeyPairContainer with keys in PEM format', function (this: Context) {
            const userKeyPairContainer: UserKeyPairContainer = Crypto.encryptPrivateKey(this.plainUserKeyPairContainer, this.password);

            expect(userKeyPairContainer.privateKeyContainer.privateKey).toContain('-----BEGIN ENCRYPTED PRIVATE KEY-----');
            expect(userKeyPairContainer.privateKeyContainer.privateKey).toContain('-----END ENCRYPTED PRIVATE KEY-----');
            expect(userKeyPairContainer.publicKeyContainer.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
            expect(userKeyPairContainer.publicKeyContainer.publicKey).toContain('-----END PUBLIC KEY-----');
        });
        it('should return a UserKeyPairContainer with identical public key', function (this: Context) {
            const userKeyPairContainer: UserKeyPairContainer = Crypto.encryptPrivateKey(this.plainUserKeyPairContainer, this.password);

            expect(userKeyPairContainer.publicKeyContainer.publicKey).toEqual(this.plainUserKeyPairContainer.publicKeyContainer.publicKey);
        });
    });
});
