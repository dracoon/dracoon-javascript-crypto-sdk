import base64 from 'base64-js';
import { Crypto } from '../../src/Crypto';
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
    describe('with a valid filekey', () => {
        beforeEach(function (this: Context) {
            this.plainFileKey = plainFileKey as PlainFileKey;
            this.fileDecryptionCipher = Crypto.createFileDecryptionCipher(this.plainFileKey);
        });
        it('should decrypt a string in a single chunk', function (this: Context) {
            const encryptedByteArray: Uint8Array = base64.toByteArray(encryptedFileContentsB64);
            const encryptedDataContainer: EncryptedDataContainer = new EncryptedDataContainer(encryptedByteArray);

            const plainDataContainer1: PlainDataContainer = this.fileDecryptionCipher.processBytes(encryptedDataContainer);
            const plainDataContainer2: PlainDataContainer = this.fileDecryptionCipher.doFinal();

            const plainByteArray: Uint8Array = new Uint8Array([...plainDataContainer1.getContent(), ...plainDataContainer2.getContent()]);
            const plainStringB64: string = base64.fromByteArray(plainByteArray);

            expect(plainStringB64).toEqual(plainFileContentsB64);
        });
        it('should decrypt a string in multiple chunks', function (this: Context) {
            const encryptedByteArray: Uint8Array = base64.toByteArray(encryptedFileContentsB64);
            const encryptedByteArray1: Uint8Array = encryptedByteArray.slice(0, 22);
            const encryptedByteArray2: Uint8Array = encryptedByteArray.slice(22, 44);
            const encryptedDataContainer1: EncryptedDataContainer = new EncryptedDataContainer(encryptedByteArray1);
            const encryptedDataContainer2: EncryptedDataContainer = new EncryptedDataContainer(encryptedByteArray2);

            const plainDataContainer1: PlainDataContainer = this.fileDecryptionCipher.processBytes(encryptedDataContainer1);
            const plainDataContainer2: PlainDataContainer = this.fileDecryptionCipher.processBytes(encryptedDataContainer2);
            const plainDataContainer3: PlainDataContainer = this.fileDecryptionCipher.doFinal();

            const plainByteArray: Uint8Array = new Uint8Array([
                ...plainDataContainer1.getContent(),
                ...plainDataContainer2.getContent(),
                ...plainDataContainer3.getContent()
            ]);
            const plainStringB64: string = base64.fromByteArray(plainByteArray);

            expect(plainStringB64).toEqual(plainFileContentsB64);
        });
    });
    describe('with an invalid filekey', () => {
        it('should throw a DecryptionError, if filekey has a modified tag', function (this: Context) {
            this.plainFileKey = plainFileKeyBadTag as PlainFileKey;
            this.fileDecryptionCipher = Crypto.createFileDecryptionCipher(this.plainFileKey);
            let someError = null;

            try {
                const encryptedByteArray: Uint8Array = base64.toByteArray(encryptedFileContentsB64);
                const encryptedDataContainer: EncryptedDataContainer = new EncryptedDataContainer(encryptedByteArray);

                this.fileDecryptionCipher.processBytes(encryptedDataContainer);
                this.fileDecryptionCipher.doFinal();
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(DecryptionError);
        });
        it('should throw a DecryptionError, if filekey has a modified key', function (this: Context) {
            this.plainFileKey = plainFileKeyBadKey as PlainFileKey;
            this.fileDecryptionCipher = Crypto.createFileDecryptionCipher(this.plainFileKey);
            let someError = null;

            try {
                const encryptedByteArray: Uint8Array = base64.toByteArray(encryptedFileContentsB64);
                const encryptedDataContainer: EncryptedDataContainer = new EncryptedDataContainer(encryptedByteArray);

                this.fileDecryptionCipher.processBytes(encryptedDataContainer);
                this.fileDecryptionCipher.doFinal();
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(DecryptionError);
        });
        it('should throw a DecryptionError, if filekey has a modified iv', function (this: Context) {
            this.plainFileKey = plainFileKeyBadIv as PlainFileKey;
            this.fileDecryptionCipher = Crypto.createFileDecryptionCipher(this.plainFileKey);
            let someError = null;

            try {
                const encryptedByteArray: Uint8Array = base64.toByteArray(encryptedFileContentsB64);
                const encryptedDataContainer: EncryptedDataContainer = new EncryptedDataContainer(encryptedByteArray);

                this.fileDecryptionCipher.processBytes(encryptedDataContainer);
                this.fileDecryptionCipher.doFinal();
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(DecryptionError);
        });
    });
});
