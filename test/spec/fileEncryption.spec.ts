import base64 from 'base64-js';
import { Crypto } from '../../src/index';
import { EncryptedDataContainer } from '../../src/EncryptedDataContainer';
import { FileEncryptionCipher } from '../../src/FileEncryptionCipher';
import { PlainDataContainer } from '../../src/PlainDataContainer';
import { PlainFileKey } from '../../src/models/PlainFileKey';

import plainFileKey from '../keys/javascript/fk_rsa2048_aes256gcm/plain_file_key.json';

const encryptedFileContentsB64: string = 'E3lVnT+CKTRZlm+zkuNi6B6vHazTjBaMBPeGPHNV113p0wocqD+a5wUy3b8=';
const plainFileContentsB64: string = 'VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4=';

type Context = {
    plainFileKey: PlainFileKey;
    fileEncryptionCipher: FileEncryptionCipher;
};

describe('File Encryption', () => {
    let testContext: Context;

    beforeEach(() => {
        testContext = {} as Context;
    });

    describe('with a valid filekey', () => {
        beforeEach(() => {
            testContext.plainFileKey = plainFileKey as PlainFileKey;
            testContext.fileEncryptionCipher = Crypto.createFileEncryptionCipher(testContext.plainFileKey);
        });
        test('should encrypt a string in a single chunk', () => {
            const plainByteArray: Uint8Array = base64.toByteArray(plainFileContentsB64);
            const plainDataContainer: PlainDataContainer = new PlainDataContainer(plainByteArray);

            const encryptedDataContainer1: EncryptedDataContainer = testContext.fileEncryptionCipher.processBytes(plainDataContainer);
            const encryptedDataContainer2: EncryptedDataContainer = testContext.fileEncryptionCipher.doFinal();

            const encryptedByteArray: Uint8Array = new Uint8Array([
                ...encryptedDataContainer1.getContent(),
                ...encryptedDataContainer2.getContent()
            ]);
            const encryptedStringB64: string = base64.fromByteArray(encryptedByteArray);
            const tag: string = encryptedDataContainer2.getTag();

            expect(encryptedStringB64).toBe(encryptedFileContentsB64);
            expect(tag).toBe(testContext.plainFileKey.tag);
            expect(base64.byteLength(tag) * 8).toBe(128);
        });
        test('should encrypt a string in multiple chunks', () => {
            const plainByteArray: Uint8Array = base64.toByteArray(plainFileContentsB64);
            const plainByteArray1: Uint8Array = plainByteArray.slice(0, 22);
            const plainByteArray2: Uint8Array = plainByteArray.slice(22, 44);
            const plainDataContainer1: PlainDataContainer = new PlainDataContainer(plainByteArray1);
            const plainDataContainer2: PlainDataContainer = new PlainDataContainer(plainByteArray2);

            const encryptedDataContainer1: EncryptedDataContainer = testContext.fileEncryptionCipher.processBytes(plainDataContainer1);
            const encryptedDataContainer2: EncryptedDataContainer = testContext.fileEncryptionCipher.processBytes(plainDataContainer2);
            const encryptedDataContainer3: EncryptedDataContainer = testContext.fileEncryptionCipher.doFinal();

            const encryptedByteArray: Uint8Array = new Uint8Array([
                ...encryptedDataContainer1.getContent(),
                ...encryptedDataContainer2.getContent(),
                ...encryptedDataContainer3.getContent()
            ]);
            const encryptedStringB64: string = base64.fromByteArray(encryptedByteArray);
            const tag: string = encryptedDataContainer3.getTag();

            expect(encryptedStringB64).toBe(encryptedFileContentsB64);
            expect(tag).toBe(testContext.plainFileKey.tag);
            expect(base64.byteLength(tag) * 8).toBe(128);
        });
    });
});
