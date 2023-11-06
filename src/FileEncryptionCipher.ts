import { Base64, util, cipher } from 'node-forge';
import { EncryptedDataContainer } from './EncryptedDataContainer';
import { PlainDataContainer } from './PlainDataContainer';
import { PlainFileKeyVersion } from './enums/PlainFileKeyVersion';
import { EncryptionError } from './error/models/EncryptionError';
import { GenericCryptoError } from './error/models/GenericCryptoError';
import { InvalidArgumentError } from './error/models/InvalidArgumentError';
import { PlainFileKey } from './models/PlainFileKey';

export class FileEncryptionCipher {
    private readonly cipher: cipher.BlockCipher;

    /**
     * Initializes a new FileEncryptionCipher, which can be used to encrypt data in chunks.
     *
     * @param plainFileKey The plain file key used for the encryption process.
     */
    public constructor(plainFileKey: PlainFileKey) {
        if (plainFileKey.version === PlainFileKeyVersion.AES256GCM) {
            const decodedKey: string = util.decode64(plainFileKey.key);
            const decodedIv: string = util.decode64(plainFileKey.iv);
            this.cipher = cipher.createCipher('AES-GCM', decodedKey);
            this.cipher.start({
                iv: decodedIv,
                tagLength: 128
            });
        } else {
            throw new GenericCryptoError();
        }
    }

    /**
     * This method takes some plain data, encrypts the data and returns the encrypted data.
     *
     * @param plainDataContainer The data container, which holds the plain bytes.
     * @returns A data container, which holds the encrypted bytes.
     *
     * @throws {InvalidArgumentError} This error is thrown, if the provided data container is falsy.
     */
    public processBytes(plainDataContainer: PlainDataContainer): EncryptedDataContainer {
        if (!plainDataContainer) {
            throw new InvalidArgumentError();
        }

        const byteStringBuffer: util.ByteStringBuffer = util.createBuffer(plainDataContainer.getContent(), 'raw');
        this.cipher.update(byteStringBuffer);

        const encryptedBytes: string = this.cipher.output.getBytes();
        const encryptedByteArray: Uint8Array = util.binary.raw.decode(encryptedBytes);

        return new EncryptedDataContainer(encryptedByteArray);
    }

    /**
     * This method should be called to finish the encryption process.
     *
     * @returns A data container, which holds the final encrypted bytes.
     *
     * @throws {EncryptionError} This error is thrown, if the encryption process was not successful.
     */
    public doFinal(): EncryptedDataContainer {
        const success: boolean = this.cipher.finish();

        if (!success) {
            throw new EncryptionError();
        }

        const encryptedBytes: string = this.cipher.output.getBytes();
        const encryptedByteArray: Uint8Array = util.binary.raw.decode(encryptedBytes);

        const tag: string = this.cipher.mode.tag.getBytes();
        const tagB64: Base64 = util.encode64(tag);

        return new EncryptedDataContainer(encryptedByteArray, tagB64);
    }
}
