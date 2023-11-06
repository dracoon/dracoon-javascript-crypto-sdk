import { Base64 } from 'node-forge';
import base64 from 'base64-js';
import { Crypto } from '../../src/index.node';
import { PlainFileKeyVersion } from '../../src/enums/PlainFileKeyVersion';
import { FileKey } from '../../src/models/FileKey';
import { PlainFileKey } from '../../src/models/PlainFileKey';
import { PrivateKeyContainer } from '../../src/models/PrivateKeyContainer';

// Javascript crypto sdk keys
import encFileKey2048 from '../keys/javascript/fk_rsa2048_aes256gcm/enc_file_key.json';
import plainFileKey2048 from '../keys/javascript/fk_rsa2048_aes256gcm/plain_file_key.json';
import plainPrivateKey2048 from '../keys/javascript/kp_rsa2048/plain_private_key.json';
import encFileKey4096 from '../keys/javascript/fk_rsa4096_aes256gcm/enc_file_key.json';
import plainFileKey4096 from '../keys/javascript/fk_rsa4096_aes256gcm/plain_file_key.json';
import plainPrivateKey4096 from '../keys/javascript/kp_rsa4096/plain_private_key.json';

type Context = {
    fileKey: FileKey;
    privateKeyContainer: PrivateKeyContainer;
};

describe('Function: Crypto.decryptFileKey', () => {
    let testContext: Context;

    beforeEach(() => {
        testContext = {} as Context;
    });

    describe('when decrypting with keypair version RSA-2048 (A)', () => {
        beforeEach(() => {
            testContext.fileKey = encFileKey2048 as FileKey;
            testContext.privateKeyContainer = plainPrivateKey2048 as PrivateKeyContainer;
        });
        test('should return a PlainFileKey with the correct properties', () => {
            const plainFileKey: PlainFileKey = Crypto.decryptFileKey(testContext.fileKey, testContext.privateKeyContainer);

            expect(Object.keys(plainFileKey)).toContain('version');
            expect(Object.keys(plainFileKey)).toContain('key');
            expect(Object.keys(plainFileKey)).toContain('iv');
            expect(Object.keys(plainFileKey)).toContain('tag');
        });
        test('should return a PlainFileKey with the correct crypto version', () => {
            const plainFileKey: PlainFileKey = Crypto.decryptFileKey(testContext.fileKey, testContext.privateKeyContainer);

            expect(plainFileKey.version).toBe(PlainFileKeyVersion.AES256GCM);
        });
        test('should return a PlainFileKey with a 256 bit key base64 encoded', () => {
            const plainFileKey: PlainFileKey = Crypto.decryptFileKey(testContext.fileKey, testContext.privateKeyContainer);
            const bitLength: number = base64.byteLength(plainFileKey.key) * 8;

            expect(bitLength).toBe(256);
        });
        test('should return a PlainFileKey with a 96 bit iv base64 encoded', () => {
            const plainFileKey: PlainFileKey = Crypto.decryptFileKey(testContext.fileKey, testContext.privateKeyContainer);
            const bitLength: number = base64.byteLength(plainFileKey.iv) * 8;

            expect(bitLength).toBe(96);
        });
        test('should return a PlainFileKey with a 128 bit tag base64 encoded', () => {
            const plainFileKey: PlainFileKey = Crypto.decryptFileKey(testContext.fileKey, testContext.privateKeyContainer);
            const bitLength: number = base64.byteLength(plainFileKey.tag as Base64) * 8;

            expect(bitLength).toBe(128);
        });
        test('should return a PlainFileKey identical to the original key', () => {
            const plainFileKey: PlainFileKey = Crypto.decryptFileKey(testContext.fileKey, testContext.privateKeyContainer);

            expect(plainFileKey).toEqual(plainFileKey2048 as PlainFileKey);
        });
    });
    describe('when decrypting with keypair version RSA-4096', () => {
        beforeEach(() => {
            testContext.fileKey = encFileKey4096 as FileKey;
            testContext.privateKeyContainer = plainPrivateKey4096 as PrivateKeyContainer;
        });
        test('should return a PlainFileKey with the correct properties', () => {
            const plainFileKey: PlainFileKey = Crypto.decryptFileKey(testContext.fileKey, testContext.privateKeyContainer);

            expect(Object.keys(plainFileKey)).toContain('version');
            expect(Object.keys(plainFileKey)).toContain('key');
            expect(Object.keys(plainFileKey)).toContain('iv');
            expect(Object.keys(plainFileKey)).toContain('tag');
        });
        test('should return a PlainFileKey with the correct crypto version', () => {
            const plainFileKey: PlainFileKey = Crypto.decryptFileKey(testContext.fileKey, testContext.privateKeyContainer);

            expect(plainFileKey.version).toBe(PlainFileKeyVersion.AES256GCM);
        });
        test('should return a PlainFileKey with a 256 bit key base64 encoded', () => {
            const plainFileKey: PlainFileKey = Crypto.decryptFileKey(testContext.fileKey, testContext.privateKeyContainer);
            const bitLength: number = base64.byteLength(plainFileKey.key) * 8;

            expect(bitLength).toBe(256);
        });
        test('should return a PlainFileKey with a 96 bit iv base64 encoded', () => {
            const plainFileKey: PlainFileKey = Crypto.decryptFileKey(testContext.fileKey, testContext.privateKeyContainer);
            const bitLength: number = base64.byteLength(plainFileKey.iv) * 8;

            expect(bitLength).toBe(96);
        });
        test('should return a PlainFileKey with a 128 bit tag base64 encoded', () => {
            const plainFileKey: PlainFileKey = Crypto.decryptFileKey(testContext.fileKey, testContext.privateKeyContainer);
            const bitLength: number = base64.byteLength(plainFileKey.tag as Base64) * 8;

            expect(bitLength).toBe(128);
        });
        test('should return a PlainFileKey identical to the original key', () => {
            const plainFileKey: PlainFileKey = Crypto.decryptFileKey(testContext.fileKey, testContext.privateKeyContainer);

            expect(plainFileKey).toEqual(plainFileKey4096 as PlainFileKey);
        });
    });
});
