import base64 from 'base64-js';
import { Crypto } from '../../src/Crypto';
import { FileKeyVersion } from '../../src/enums/FileKeyVersion';
import { FileKey } from '../../src/models/FileKey';
import { PlainFileKey } from '../../src/models/PlainFileKey';
import { PublicKeyContainer } from '../../src/models/PublicKeyContainer';

// Javascript crypto sdk keys
import plainFileKey2048 from '../keys/javascript/fk_rsa2048_aes256gcm/plain_file_key.json';
import publicKey2048 from '../keys/javascript/kp_rsa2048/public_key.json';
import plainFileKey4096 from '../keys/javascript/fk_rsa4096_aes256gcm/plain_file_key.json';
import publicKey4096 from '../keys/javascript/kp_rsa4096/public_key.json';

type Context = {
    plainFileKey: PlainFileKey;
    publicKeyContainer: PublicKeyContainer;
};

describe('Function: Crypto.encryptFileKey', () => {
    describe('when encrypting with keypair version RSA-2048 (A)', () => {
        beforeEach(function (this: Context) {
            this.plainFileKey = plainFileKey2048 as PlainFileKey;
            this.publicKeyContainer = publicKey2048 as PublicKeyContainer;
        });
        it('should return a FileKey with the correct properties', function (this: Context) {
            const fileKey: FileKey = Crypto.encryptFileKey(this.plainFileKey, this.publicKeyContainer);

            expect(Object.keys(fileKey)).toContain('version');
            expect(Object.keys(fileKey)).toContain('key');
            expect(Object.keys(fileKey)).toContain('iv');
            expect(Object.keys(fileKey)).toContain('tag');
        });
        it('should return a FileKey with the correct crypto version', function (this: Context) {
            const fileKey: FileKey = Crypto.encryptFileKey(this.plainFileKey, this.publicKeyContainer);

            expect(fileKey.version).toEqual(FileKeyVersion.RSA2048_AES256GCM);
        });
        it('should return a FileKey with a 2048 bit key base64 encoded', function (this: Context) {
            const fileKey: FileKey = Crypto.encryptFileKey(this.plainFileKey, this.publicKeyContainer);
            const bitLength: number = base64.byteLength(fileKey.key) * 8;

            expect(bitLength).toEqual(2048);
        });
        it('should return a FileKey with a 96 bit iv base64 encoded', function (this: Context) {
            const fileKey: FileKey = Crypto.encryptFileKey(this.plainFileKey, this.publicKeyContainer);
            const bitLength: number = base64.byteLength(fileKey.iv) * 8;

            expect(bitLength).toEqual(96);
        });
        it('should return a FileKey with a 128 bit tag base64 encoded', function (this: Context) {
            const fileKey: FileKey = Crypto.encryptFileKey(this.plainFileKey, this.publicKeyContainer);
            const bitLength: number = base64.byteLength(fileKey.tag) * 8;

            expect(bitLength).toEqual(128);
        });
    });
    describe('when encrypting with keypair version RSA-4096', () => {
        beforeEach(function (this: Context) {
            this.plainFileKey = plainFileKey4096 as PlainFileKey;
            this.publicKeyContainer = publicKey4096 as PublicKeyContainer;
        });
        it('should return a FileKey with the correct properties', function (this: Context) {
            const fileKey: FileKey = Crypto.encryptFileKey(this.plainFileKey, this.publicKeyContainer);

            expect(Object.keys(fileKey)).toContain('version');
            expect(Object.keys(fileKey)).toContain('key');
            expect(Object.keys(fileKey)).toContain('iv');
            expect(Object.keys(fileKey)).toContain('tag');
        });
        it('should return a FileKey with the correct crypto version', function (this: Context) {
            const fileKey: FileKey = Crypto.encryptFileKey(this.plainFileKey, this.publicKeyContainer);

            expect(fileKey.version).toEqual(FileKeyVersion.RSA4096_AES256GCM);
        });
        it('should return a FileKey with a 4096 bit key base64 encoded', function (this: Context) {
            const fileKey: FileKey = Crypto.encryptFileKey(this.plainFileKey, this.publicKeyContainer);
            const bitLength: number = base64.byteLength(fileKey.key) * 8;

            expect(bitLength).toEqual(4096);
        });
        it('should return a FileKey with a 96 bit iv base64 encoded', function (this: Context) {
            const fileKey: FileKey = Crypto.encryptFileKey(this.plainFileKey, this.publicKeyContainer);
            const bitLength: number = base64.byteLength(fileKey.iv) * 8;

            expect(bitLength).toEqual(96);
        });
        it('should return a FileKey with a 128 bit tag base64 encoded', function (this: Context) {
            const fileKey: FileKey = Crypto.encryptFileKey(this.plainFileKey, this.publicKeyContainer);
            const bitLength: number = base64.byteLength(fileKey.tag) * 8;

            expect(bitLength).toEqual(128);
        });
    });
});
