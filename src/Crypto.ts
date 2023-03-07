import { FileDecryptionCipher } from './FileDecryptionCipher';
import { FileEncryptionCipher } from './FileEncryptionCipher';

import { PlainFileKeyVersion } from './enums/PlainFileKeyVersion';
import { UserKeyPairVersion } from './enums/UserKeyPairVersion';

import { DecryptionError } from './error/models/DecryptionError';
import { EncryptionError } from './error/models/EncryptionError';
import { GenericCryptoError } from './error/models/GenericCryptoError';
import { InvalidArgumentError } from './error/models/InvalidArgumentError';
import { InvalidFileKeyError } from './error/models/InvalidFileKeyError';
import { InvalidKeyPairError } from './error/models/InvalidKeyPairError';
import { InvalidVersionError } from './error/models/InvalidVersionError';
import { VersionMismatchError } from './error/models/VersionMismatchError';

import { decryptFileKey } from './internal/decryptFileKey';
import { decryptPrivateKey, decryptPrivateKeyOnly } from './internal/decryptPrivateKey';
import { encryptFileKey } from './internal/encryptFileKey';
import { encryptPrivateKey } from './internal/encryptPrivateKey';
import { generateFileKey } from './internal/generateFileKey';
import { generatePlainUserKeyPair } from './internal/generatePlainUserKeyPair';
import { initCryptoVersionChecker } from './internal/initCryptoVersionChecker';

import { FileKey } from './models/FileKey';
import { PlainFileKey } from './models/PlainFileKey';
import { PlainUserKeyPairContainer } from './models/PlainUserKeyPairContainer';
import { PrivateKeyContainer } from './models/PrivateKeyContainer';
import { PublicKeyContainer } from './models/PublicKeyContainer';
import { UserKeyPairContainer } from './models/UserKeyPairContainer';

import { CryptoFileKeyChecker } from './utils/CryptoFileKeyChecker';
import { CryptoKeyPairChecker } from './utils/CryptoKeyPairChecker';
import { CryptoVersionChecker } from './utils/CryptoVersionChecker';

export class Crypto {
    private static cryptoVersionChecker: CryptoVersionChecker;

    /**
     * Private constructor.
     * This class only provides access to static methods and therefore does not need to be initialized.
     */
    private constructor() {
        throw new Error('Crypto must not be initialized.');
    }

    /**
     * This method generates a new user key pair with an encrypted private key.
     *
     * @param version The version of the key pair that should be generated.
     * @param password The password used for encrypting the private key of the generated key pair.
     * @returns A promise that resolves to the generated key pair.
     *
     * @throws {InvalidArgumentError} This error is thrown, if a required argument has a falsy value.
     * @throws {InvalidVersionError} This error is thrown, if the provided version is not supported.
     */
    public static async generateUserKeyPair(version: UserKeyPairVersion, password: string): Promise<UserKeyPairContainer> {
        Crypto.init();

        if (!version || !password) {
            throw new InvalidArgumentError();
        }

        if (!Object.values(UserKeyPairVersion).includes(version)) {
            throw new InvalidVersionError();
        }

        try {
            const plainUserKeyPair = await generatePlainUserKeyPair(version);
            return encryptPrivateKey(plainUserKeyPair, password);
        } catch (error) {
            throw new GenericCryptoError();
        }
    }

    /**
     * This method encrypts a given plain key pair with a given password.
     *
     * @param plainUserKeyPairContainer The plain key pair that should be encrypted.
     * @param password The password that should be used for the encryption.
     * @returns The key pair that contains the encrypted private key.
     *
     * @throws {InvalidArgumentError} This error is thrown, if a required argument has a falsy value.
     * @throws {InvalidKeyPairError} This error is thrown, if the provided key pair is invalid.
     * @throws {EncryptionError} This error is thrown, if the actual encryption fails.
     */
    public static encryptPrivateKey(plainUserKeyPairContainer: PlainUserKeyPairContainer, password: string): UserKeyPairContainer {
        Crypto.init();

        if (!plainUserKeyPairContainer || !password) {
            throw new InvalidArgumentError();
        }

        const keyPairValid: boolean = CryptoKeyPairChecker.checkKeyPairContainer(plainUserKeyPairContainer);
        if (!keyPairValid) {
            throw new InvalidKeyPairError();
        }

        try {
            return encryptPrivateKey(plainUserKeyPairContainer, password);
        } catch (error) {
            throw new EncryptionError();
        }
    }

    /**
     * This method decrypts a given key pair with a given password.
     *
     * @param userKeyPairContainer The key pair that should be decrypted.
     * @param password The password that should be used for the decryption.
     * @returns The plain key pair that contains the unencrypted private key.
     *
     * @throws {InvalidArgumentError} This error is thrown, if a required argument has a falsy value.
     * @throws {InvalidKeyPairError} This error is thrown, if the provided key pair is invalid.
     * @throws {DecryptionError} This error is thrown, if the actual decryption fails.
     */
    public static decryptPrivateKey(userKeyPairContainer: UserKeyPairContainer, password: string): PlainUserKeyPairContainer {
        Crypto.init();

        if (!userKeyPairContainer || !password) {
            throw new InvalidArgumentError();
        }

        const keyPairValid: boolean = CryptoKeyPairChecker.checkKeyPairContainer(userKeyPairContainer);
        if (!keyPairValid) {
            throw new InvalidKeyPairError();
        }

        try {
            return decryptPrivateKey(userKeyPairContainer, password);
        } catch (error) {
            throw new DecryptionError();
        }
    }

    /**
     * This method decrypts a given key pair with a given password.
     *
     * @param privateKeyContainer The key pair that should be decrypted.
     * @param password The password that should be used for the decryption.
     * @returns The plain key pair that contains the unencrypted private key.
     *
     * @throws {InvalidArgumentError} This error is thrown, if a required argument has a falsy value.
     * @throws {InvalidKeyPairError} This error is thrown, if the provided private key container is invalid.
     * @throws {DecryptionError} This error is thrown, if the actual decryption fails.
     */
    public static decryptPrivateKeyOnly(privateKeyContainer: PrivateKeyContainer, password: string): PrivateKeyContainer {
        Crypto.init();

        if (!privateKeyContainer || !password) {
            throw new InvalidArgumentError();
        }

        const keyValid: boolean = CryptoKeyPairChecker.checkKeyContainer(privateKeyContainer);
        if (!keyValid) {
            throw new InvalidKeyPairError();
        }

        try {
            return decryptPrivateKeyOnly(privateKeyContainer, password);
        } catch (error) {
            throw new DecryptionError();
        }
    }

    /**
     * This method checks, if a given key pair can be decrypted with a given password.
     *
     * @param userKeyPairContainer The key pair that should be checked.
     * @param password The password that should be used for the check.
     * @returns Either true or false depending on, if the private key of the key pair can be decrypted.
     *
     * @throws {InvalidArgumentError} This error is thrown, if a required argument has a falsy value.
     * @throws {InvalidKeyPairError} This error is thrown, if the provided key pair is invalid.
     */
    public static checkUserKeyPair(userKeyPairContainer: UserKeyPairContainer, password: string): boolean {
        Crypto.init();

        if (!userKeyPairContainer || !password) {
            throw new InvalidArgumentError();
        }

        const keyPairValid: boolean = CryptoKeyPairChecker.checkKeyPairContainer(userKeyPairContainer);
        if (!keyPairValid) {
            throw new InvalidKeyPairError();
        }

        try {
            return !!decryptPrivateKey(userKeyPairContainer, password);
        } catch (error) {
            return false;
        }
    }

    /**
     * This method generates a new file key.
     *
     * @param version The version of the plain file key that should be generated.
     * @returns A plain file key.
     *
     * @throws {InvalidArgumentError} This error is thrown, if a required argument has a falsy value.
     * @throws {InvalidVersionError} This error is thrown, if the provided version is not supported.
     */
    public static generateFileKey(version: PlainFileKeyVersion): PlainFileKey {
        Crypto.init();

        if (!version) {
            throw new InvalidArgumentError();
        }

        if (!Object.values(PlainFileKeyVersion).includes(version)) {
            throw new InvalidVersionError();
        }

        try {
            return generateFileKey(version);
        } catch (error) {
            throw new GenericCryptoError();
        }
    }

    /**
     * This method encrypts a given file key with a given public key.
     *
     * @param plainFileKey The plain file key that should be encrypted.
     * @param publicKeyContainer The public key container, that contains the public key used for encrypting the plain file key.
     * @returns The encrypted file key after encryption.
     *
     * @throws {InvalidArgumentError} This error is thrown, if a required argument has a falsy value.
     * @throws {InvalidFileKeyError} This error is thrown, if the provided file key is invalid.
     * @throws {InvalidKeyPairError} This error is thrown, if the provided key pair is invalid.
     * @throws {EncryptionError} This error is thrown, if the actual encryption fails.
     * @throws {VersionMismatchError} This error is thrown, if the file key and private key are not compatible.
     */
    public static encryptFileKey(plainFileKey: PlainFileKey, publicKeyContainer: PublicKeyContainer): FileKey {
        Crypto.init();

        if (!plainFileKey || !publicKeyContainer) {
            throw new InvalidArgumentError();
        }

        const fileKeyValid: boolean = CryptoFileKeyChecker.checkPlainFileKey(plainFileKey);
        if (!fileKeyValid) {
            throw new InvalidFileKeyError();
        }
        const publicKeyValid: boolean = CryptoKeyPairChecker.checkKeyContainer(publicKeyContainer);
        if (!publicKeyValid) {
            throw new InvalidKeyPairError();
        }

        try {
            return encryptFileKey(plainFileKey, publicKeyContainer, Crypto.cryptoVersionChecker);
        } catch (error) {
            if (error instanceof VersionMismatchError) {
                throw error;
            } else {
                throw new EncryptionError();
            }
        }
    }

    /**
     * This method decrypts a given file key with a given private key.
     *
     * @param fileKey The file key that should be decrypted.
     * @param privateKeyContainer The private key container, that contains the private key used for decrypting the file key.
     * @returns The plain file key after decryption.
     *
     * @throws {InvalidArgumentError} This error is thrown, if a required argument has a falsy value.
     * @throws {InvalidFileKeyError} This error is thrown, if the provided file key is invalid.
     * @throws {InvalidKeyPairError} This error is thrown, if the provided key pair is invalid.
     * @throws {DecryptionError} This error is thrown, if the actual decryption fails.
     * @throws {VersionMismatchError} This error is thrown, if the file key and private key are not compatible.
     */
    public static decryptFileKey(fileKey: FileKey, privateKeyContainer: PrivateKeyContainer): PlainFileKey {
        Crypto.init();

        if (!fileKey || !privateKeyContainer) {
            throw new InvalidArgumentError();
        }

        const fileKeyValid: boolean = CryptoFileKeyChecker.checkFileKey(fileKey);
        if (!fileKeyValid) {
            throw new InvalidFileKeyError();
        }
        const privateKeyValid: boolean = CryptoKeyPairChecker.checkKeyContainer(privateKeyContainer);
        if (!privateKeyValid) {
            throw new InvalidKeyPairError();
        }

        try {
            return decryptFileKey(fileKey, privateKeyContainer, Crypto.cryptoVersionChecker);
        } catch (error) {
            if (error instanceof VersionMismatchError) {
                throw error;
            } else {
                throw new DecryptionError();
            }
        }
    }

    /**
     * This method creates a new file encryption cipher that can be used to symmetrically encrypt data in chunks.
     *
     * @param plainFileKey The plain file key that should be used for the encryption process.
     * @returns A file encryption cipher that can be used to encrypt data.
     *
     * @throws {InvalidArgumentError} This error is thrown, if a required argument has a falsy value.
     * @throws {InvalidFileKeyError} This error is thrown, if the provided file key is invalid.
     */
    public static createFileEncryptionCipher(plainFileKey: PlainFileKey): FileEncryptionCipher {
        Crypto.init();

        if (!plainFileKey) {
            throw new InvalidArgumentError();
        }

        const fileKeyValid: boolean = CryptoFileKeyChecker.checkPlainFileKey(plainFileKey);
        if (!fileKeyValid) {
            throw new InvalidFileKeyError();
        }

        try {
            return new FileEncryptionCipher(plainFileKey);
        } catch (error) {
            throw new GenericCryptoError();
        }
    }

    /**
     * This method creates a new file decryption cipher that can be used to symmetrically decrypt data in chunks.
     *
     * @param plainFileKey The plain file key that should be used for the decryption process.
     * @returns A file decryption cipher that can be used to decrypt data.
     *
     * @throws {InvalidArgumentError} This error is thrown, if a required argument has a falsy value.
     * @throws {InvalidFileKeyError} This error is thrown, if the provided file key is invalid.
     */
    public static createFileDecryptionCipher(plainFileKey: PlainFileKey): FileDecryptionCipher {
        Crypto.init();

        if (!plainFileKey) {
            throw new InvalidArgumentError();
        }

        const fileKeyValid: boolean = CryptoFileKeyChecker.checkPlainFileKey(plainFileKey);
        if (!fileKeyValid) {
            throw new InvalidFileKeyError();
        }

        try {
            return new FileDecryptionCipher(plainFileKey);
        } catch (error) {
            throw new GenericCryptoError();
        }
    }

    /**
     * Initializes internal private members needed for crypto operations, if not already set.
     */
    private static init(): void {
        if (!Crypto.cryptoVersionChecker) {
            Crypto.cryptoVersionChecker = initCryptoVersionChecker();
        }
    }
}
