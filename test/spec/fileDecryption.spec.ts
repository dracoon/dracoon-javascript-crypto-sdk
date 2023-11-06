import base64 from 'base64-js';
import { Crypto } from '../../src/index.node';
import { EncryptedDataContainer } from '../../src/EncryptedDataContainer';
import { PlainDataContainer } from '../../src/PlainDataContainer';
import { FileDecryptionCipher } from '../../src/FileDecryptionCipher';
import { DecryptionError } from '../../src/error/models/DecryptionError';
import { PlainFileKey } from '../../src/models/PlainFileKey';

import plainFileKey from '../keys/javascript/fk_rsa2048_aes256gcm/plain_file_key.json';
import plainFileKeyBadTag from '../keys/corrupted/plain_file_key_bad_tag.json';
import plainFileKeyBadKey from '../keys/corrupted/plain_file_key_bad_key.json';
import plainFileKeyBadIv from '../keys/corrupted/plain_file_key_bad_iv.json';

const encryptedFileContentsB64: string = 'E3lVnT+CKTRZlm+zkuNi6B6vHazTjBaMBPeGPHNV113p0wocqD+a5wUy3b8=';
const plainFileContentsB64: string = 'VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4=';

type Context = {
    plainFileKey: PlainFileKey;
    fileDecryptionCipher: FileDecryptionCipher;
};

describe('File Decryption', () => {
    let testContext: Context;

    beforeEach(() => {
        testContext = {} as Context;
    });

    describe('with a valid filekey', () => {
        beforeEach(() => {
            testContext.plainFileKey = plainFileKey as PlainFileKey;
            testContext.fileDecryptionCipher = Crypto.createFileDecryptionCipher(testContext.plainFileKey);
        });
        test('should decrypt a string in a single chunk', async () => {
            const encryptedByteArray: Uint8Array = base64.toByteArray(encryptedFileContentsB64);
            const encryptedDataContainer: EncryptedDataContainer = new EncryptedDataContainer(encryptedByteArray);

            const plainDataContainer1: PlainDataContainer = testContext.fileDecryptionCipher.processBytes(encryptedDataContainer);
            const plainDataContainer2: PlainDataContainer = testContext.fileDecryptionCipher.doFinal();

            const plainByteArray: Uint8Array = new Uint8Array([...plainDataContainer1.getContent(), ...plainDataContainer2.getContent()]);
            const plainStringB64: string = base64.fromByteArray(plainByteArray);

            expect(plainStringB64).toBe(plainFileContentsB64);
        });
        test('should decrypt a string in multiple chunks', () => {
            const encryptedByteArray: Uint8Array = base64.toByteArray(encryptedFileContentsB64);
            const encryptedByteArray1: Uint8Array = encryptedByteArray.slice(0, 22);
            const encryptedByteArray2: Uint8Array = encryptedByteArray.slice(22, 44);
            const encryptedDataContainer1: EncryptedDataContainer = new EncryptedDataContainer(encryptedByteArray1);
            const encryptedDataContainer2: EncryptedDataContainer = new EncryptedDataContainer(encryptedByteArray2);

            const plainDataContainer1: PlainDataContainer = testContext.fileDecryptionCipher.processBytes(encryptedDataContainer1);
            const plainDataContainer2: PlainDataContainer = testContext.fileDecryptionCipher.processBytes(encryptedDataContainer2);
            const plainDataContainer3: PlainDataContainer = testContext.fileDecryptionCipher.doFinal();

            const plainByteArray: Uint8Array = new Uint8Array([
                ...plainDataContainer1.getContent(),
                ...plainDataContainer2.getContent(),
                ...plainDataContainer3.getContent()
            ]);
            const plainStringB64: string = base64.fromByteArray(plainByteArray);

            expect(plainStringB64).toBe(plainFileContentsB64);
        });
    });
    describe('with an invalid filekey', () => {
        test('should throw a DecryptionError, if filekey has a modified tag', () => {
            testContext.plainFileKey = plainFileKeyBadTag as PlainFileKey;
            testContext.fileDecryptionCipher = Crypto.createFileDecryptionCipher(testContext.plainFileKey);
            let someError = null;

            try {
                const encryptedByteArray: Uint8Array = base64.toByteArray(encryptedFileContentsB64);
                const encryptedDataContainer: EncryptedDataContainer = new EncryptedDataContainer(encryptedByteArray);

                testContext.fileDecryptionCipher.processBytes(encryptedDataContainer);
                testContext.fileDecryptionCipher.doFinal();
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(DecryptionError);
        });
        test('should throw a DecryptionError, if filekey has a modified key', () => {
            testContext.plainFileKey = plainFileKeyBadKey as PlainFileKey;
            testContext.fileDecryptionCipher = Crypto.createFileDecryptionCipher(testContext.plainFileKey);
            let someError = null;

            try {
                const encryptedByteArray: Uint8Array = base64.toByteArray(encryptedFileContentsB64);
                const encryptedDataContainer: EncryptedDataContainer = new EncryptedDataContainer(encryptedByteArray);

                testContext.fileDecryptionCipher.processBytes(encryptedDataContainer);
                testContext.fileDecryptionCipher.doFinal();
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(DecryptionError);
        });
        test('should throw a DecryptionError, if filekey has a modified iv', () => {
            testContext.plainFileKey = plainFileKeyBadIv as PlainFileKey;
            testContext.fileDecryptionCipher = Crypto.createFileDecryptionCipher(testContext.plainFileKey);
            let someError = null;

            try {
                const encryptedByteArray: Uint8Array = base64.toByteArray(encryptedFileContentsB64);
                const encryptedDataContainer: EncryptedDataContainer = new EncryptedDataContainer(encryptedByteArray);

                testContext.fileDecryptionCipher.processBytes(encryptedDataContainer);
                testContext.fileDecryptionCipher.doFinal();
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(DecryptionError);
        });
    });
});
