import { Crypto } from '../../src/Crypto';
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
    describe('with keypair version RSA-2048 (A)', () => {
        beforeEach(function (this: Context) {
            this.userKeyPairContainer = {
                privateKeyContainer: privateKey2048 as PrivateKeyContainer,
                publicKeyContainer: publicKey2048 as PublicKeyContainer
            };
            this.password = 'Qwer1234!';
        });
        it('should return a PlainUserKeyPairContainer with the correct properties', function (this: Context) {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(this.userKeyPairContainer, this.password);

            expect(Object.keys(plainUserKeyPairContainer)).toContain('privateKeyContainer');
            expect(Object.keys(plainUserKeyPairContainer)).toContain('publicKeyContainer');
            expect(Object.keys(plainUserKeyPairContainer.privateKeyContainer)).toContain('version');
            expect(Object.keys(plainUserKeyPairContainer.privateKeyContainer)).toContain('privateKey');
            expect(Object.keys(plainUserKeyPairContainer.publicKeyContainer)).toContain('version');
            expect(Object.keys(plainUserKeyPairContainer.publicKeyContainer)).toContain('publicKey');
        });
        it('should return a PlainUserKeyPairContainer with the correct crypto version', function (this: Context) {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(this.userKeyPairContainer, this.password);

            expect(plainUserKeyPairContainer.privateKeyContainer.version).toEqual(UserKeyPairVersion.RSA2048);
            expect(plainUserKeyPairContainer.publicKeyContainer.version).toEqual(UserKeyPairVersion.RSA2048);
        });
        it('should return a PlainUserKeyPairContainer with keys in PEM format', function (this: Context) {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(this.userKeyPairContainer, this.password);

            expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----BEGIN RSA PRIVATE KEY-----');
            expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----END RSA PRIVATE KEY-----');
            expect(plainUserKeyPairContainer.publicKeyContainer.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
            expect(plainUserKeyPairContainer.publicKeyContainer.publicKey).toContain('-----END PUBLIC KEY-----');
        });
        it('should return a PlainUserKeyPairContainer with identical public key', function (this: Context) {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(this.userKeyPairContainer, this.password);

            expect(plainUserKeyPairContainer.publicKeyContainer.publicKey).toEqual(this.userKeyPairContainer.publicKeyContainer.publicKey);
        });
        it('should return a PlainUserKeyPairContainer with the correct plain private key', function (this: Context) {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(this.userKeyPairContainer, this.password);

            expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toEqual(plainPrivateKey2048.privateKey);
        });
    });
    describe('with keypair version RSA-4096', () => {
        beforeEach(function (this: Context) {
            this.userKeyPairContainer = {
                privateKeyContainer: privateKey4096 as PrivateKeyContainer,
                publicKeyContainer: publicKey4096 as PublicKeyContainer
            };
            this.password = 'Qwer1234!';
        });
        it('should return a PlainUserKeyPairContainer with the correct properties', function (this: Context) {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(this.userKeyPairContainer, this.password);

            expect(Object.keys(plainUserKeyPairContainer)).toContain('privateKeyContainer');
            expect(Object.keys(plainUserKeyPairContainer)).toContain('publicKeyContainer');
            expect(Object.keys(plainUserKeyPairContainer.privateKeyContainer)).toContain('version');
            expect(Object.keys(plainUserKeyPairContainer.privateKeyContainer)).toContain('privateKey');
            expect(Object.keys(plainUserKeyPairContainer.publicKeyContainer)).toContain('version');
            expect(Object.keys(plainUserKeyPairContainer.publicKeyContainer)).toContain('publicKey');
        });
        it('should return a PlainUserKeyPairContainer with the correct crypto version', function (this: Context) {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(this.userKeyPairContainer, this.password);

            expect(plainUserKeyPairContainer.privateKeyContainer.version).toEqual(UserKeyPairVersion.RSA4096);
            expect(plainUserKeyPairContainer.publicKeyContainer.version).toEqual(UserKeyPairVersion.RSA4096);
        });
        it('should return a PlainUserKeyPairContainer with keys in PEM format', function (this: Context) {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(this.userKeyPairContainer, this.password);

            expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----BEGIN RSA PRIVATE KEY-----');
            expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----END RSA PRIVATE KEY-----');
            expect(plainUserKeyPairContainer.publicKeyContainer.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
            expect(plainUserKeyPairContainer.publicKeyContainer.publicKey).toContain('-----END PUBLIC KEY-----');
        });
        it('should return a PlainUserKeyPairContainer with identical public key', function (this: Context) {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(this.userKeyPairContainer, this.password);

            expect(plainUserKeyPairContainer.publicKeyContainer.publicKey).toEqual(this.userKeyPairContainer.publicKeyContainer.publicKey);
        });
        it('should return a PlainUserKeyPairContainer with the correct plain private key', function (this: Context) {
            const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(this.userKeyPairContainer, this.password);

            expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toEqual(plainPrivateKey4096.privateKey);
        });
    });
});
