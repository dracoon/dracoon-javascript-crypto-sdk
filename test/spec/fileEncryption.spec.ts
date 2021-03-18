import base64 from 'base64-js';
import { Crypto } from '../../src/Crypto';
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
    describe('with a valid filekey', () => {
        beforeEach(function (this: Context) {
            this.plainFileKey = plainFileKey as PlainFileKey;
            this.fileEncryptionCipher = Crypto.createFileEncryptionCipher(this.plainFileKey);
        });
        it('should encrypt a string in a single chunk', function (this: Context) {
            const plainByteArray: Uint8Array = base64.toByteArray(plainFileContentsB64);
            const plainDataContainer: PlainDataContainer = new PlainDataContainer(plainByteArray);

            const encryptedDataContainer1: EncryptedDataContainer = this.fileEncryptionCipher.processBytes(plainDataContainer);
            const encryptedDataContainer2: EncryptedDataContainer = this.fileEncryptionCipher.doFinal();

            const encryptedByteArray: Uint8Array = new Uint8Array([
                ...encryptedDataContainer1.getContent(),
                ...encryptedDataContainer2.getContent()
            ]);
            const encryptedStringB64: string = base64.fromByteArray(encryptedByteArray);
            const tag: string = encryptedDataContainer2.getTag();

            expect(encryptedStringB64).toEqual(encryptedFileContentsB64);
            expect(tag).toEqual(this.plainFileKey.tag);
            expect(base64.byteLength(tag) * 8).toEqual(128);
        });
        it('should encrypt a string in multiple chunks', function (this: Context) {
            const plainByteArray: Uint8Array = base64.toByteArray(plainFileContentsB64);
            const plainByteArray1: Uint8Array = plainByteArray.slice(0, 22);
            const plainByteArray2: Uint8Array = plainByteArray.slice(22, 44);
            const plainDataContainer1: PlainDataContainer = new PlainDataContainer(plainByteArray1);
            const plainDataContainer2: PlainDataContainer = new PlainDataContainer(plainByteArray2);

            const encryptedDataContainer1: EncryptedDataContainer = this.fileEncryptionCipher.processBytes(plainDataContainer1);
            const encryptedDataContainer2: EncryptedDataContainer = this.fileEncryptionCipher.processBytes(plainDataContainer2);
            const encryptedDataContainer3: EncryptedDataContainer = this.fileEncryptionCipher.doFinal();

            const encryptedByteArray: Uint8Array = new Uint8Array([
                ...encryptedDataContainer1.getContent(),
                ...encryptedDataContainer2.getContent(),
                ...encryptedDataContainer3.getContent()
            ]);
            const encryptedStringB64: string = base64.fromByteArray(encryptedByteArray);
            const tag: string = encryptedDataContainer3.getTag();

            expect(encryptedStringB64).toEqual(encryptedFileContentsB64);
            expect(tag).toEqual(this.plainFileKey.tag);
            expect(base64.byteLength(tag) * 8).toEqual(128);
        });
    });
});
