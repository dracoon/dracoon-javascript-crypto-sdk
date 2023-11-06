import { util, cipher } from 'node-forge';
import { EncryptedDataContainer } from './EncryptedDataContainer';
import { PlainDataContainer } from './PlainDataContainer';
import { PlainFileKeyVersion } from './enums/PlainFileKeyVersion';
import { DecryptionError } from './error/models/DecryptionError';
import { GenericCryptoError } from './error/models/GenericCryptoError';
import { InvalidArgumentError } from './error/models/InvalidArgumentError';
import { PlainFileKey } from './models/PlainFileKey';

export class FileDecryptionCipher {
    private readonly cipher: cipher.BlockCipher;

    /**
     * Initializes a new FileDecryptionCipher, which can be used to decrypt data in chunks.
     *
     * @param plainFileKey The plain file key used for the decryption process.
     */
    public constructor(plainFileKey: PlainFileKey) {
        if (plainFileKey.version === PlainFileKeyVersion.AES256GCM && plainFileKey.tag) {
            const decodedKey: string = util.decode64(plainFileKey.key);
            const decodedIv: string = util.decode64(plainFileKey.iv);
            const decodedTag: string = util.decode64(plainFileKey.tag);
            const tag: util.ByteStringBuffer = util.createBuffer(decodedTag);
            this.cipher = cipher.createDecipher('AES-GCM', decodedKey);
            this.cipher.start({
                iv: decodedIv,
                tagLength: 128,
                tag: tag
            });
        } else {
            throw new GenericCryptoError();
        }
    }

    /**
     * This method takes some encrypted data, decrypts the data and returns the plain data.
     *
     * @param encryptedDataContainer The data container, which holds the encrypted bytes.
     * @returns A data container, which holds the decrypted bytes.
     *
     * @throws {InvalidArgumentError} This error is thrown, if the provided data container is falsy.
     */
    public processBytes(encryptedDataContainer: EncryptedDataContainer): PlainDataContainer {
        if (!encryptedDataContainer) {
            throw new InvalidArgumentError();
        }

        const byteStringBuffer: util.ByteStringBuffer = util.createBuffer(encryptedDataContainer.getContent(), 'raw');
        this.cipher.update(byteStringBuffer);

        const decryptedBytes: string = this.cipher.output.getBytes();
        const decryptedByteArray: Uint8Array = util.binary.raw.decode(decryptedBytes);

        return new PlainDataContainer(decryptedByteArray);
    }

    /**
     * This method should be called to finish the decryption process.
     *
     * @returns A data container, which holds the final decrypted bytes.
     *
     * @throws {DecryptionError} This error is thrown, if the decryption was not successful. (e.g. wrong tag)
     */
    public doFinal(): PlainDataContainer {
        const success = this.cipher.finish();

        if (!success) {
            throw new DecryptionError();
        }

        const decryptedBytes: string = this.cipher.output.getBytes();
        const decryptedByteArray: Uint8Array = util.binary.raw.decode(decryptedBytes);

        return new PlainDataContainer(decryptedByteArray);
    }
}
