import { Crypto, EncryptedDataContainer, PlainDataContainer, PlainFileKeyVersion, UserKeyPairVersion } from '@dracoon-official/crypto-sdk';

/**
 * This file shows how to use the Dracoon JavaScript Crypto SDK.
 * For the sake of simplicity, error handling is ignored.
 *
 * IMPORTANT: please create a new file key for every file you encrypt!
 * IMPORTANT: please call doFinal() to complete decryption BEFORE using the decrypted data!
 */

const CHUNK_SIZE_BYTES = 16;
const DATA = new Uint8Array(CHUNK_SIZE_BYTES ** 2);
const USER_PASSWORD = 'Password1234!';

/**
 * Shows a complete encryption/decryption workflow.
 */
const performEncryptionDecryptionWorkflow = async () => {
    // Get plain data
    const plainData = new Uint8Array([...DATA]);
    console.log('plainData', plainData);

    // --- KEY GENERATION ---
    // Generate key pair
    const userKeyPair = await Crypto.generateUserKeyPair(UserKeyPairVersion.RSA4096, USER_PASSWORD);
    // Generate plain file key
    const plainFileKey = Crypto.generateFileKey(PlainFileKeyVersion.AES256GCM);

    // --- ENCRYPTION ---
    // Perform Encryption
    const encryptedData = performEncryption(plainFileKey, plainData);
    console.log('encryptedData', encryptedData);

    // --- KEY OPERATIONS ---
    // Encrypt file key
    const encryptedFileKey = Crypto.encryptFileKey(plainFileKey, userKeyPair.publicKeyContainer);
    // Check password
    const success = await Crypto.checkUserKeyPairAsync(userKeyPair, USER_PASSWORD);
    if (!success) {
        console.log('wrong password');
        return;
    }
    // Decrypt private key
    const plainUserKeyPair = await Crypto.decryptPrivateKeyAsync(userKeyPair, USER_PASSWORD);
    // Decrypt file key
    const decryptedFileKey = Crypto.decryptFileKey(encryptedFileKey, plainUserKeyPair.privateKeyContainer);

    // --- DECRYPTION ---
    // Perform Decryption
    const decryptedData = performDecryption(decryptedFileKey, encryptedData);
    console.log('decryptedData', decryptedData);
};

/**
 * Shows the encryption workflow.
 */
const performEncryption = (plainFileKey, plainData) => {
    // Generate file encryption cipher
    const fileEncryptionCipher = Crypto.createFileEncryptionCipher(plainFileKey);

    // Split up data into chunks
    const plainChunks = [];
    for (let startIndex = 0; startIndex < plainData.length; startIndex += CHUNK_SIZE_BYTES) {
        const endIndex = startIndex + CHUNK_SIZE_BYTES;
        plainChunks.push(plainData.slice(startIndex, endIndex));
    }

    // Encrypt chunks
    const encryptedChunks = [];
    plainChunks.forEach((chunk) => {
        const encryptedDataContainer = fileEncryptionCipher.processBytes(new PlainDataContainer(chunk));
        encryptedChunks.push(encryptedDataContainer.getContent());
    });

    // Complete encryption and get authentication tag
    plainFileKey.tag = fileEncryptionCipher.doFinal().getTag();

    // Concatenate encrypted chunks
    const concatenatedChunks = [];
    encryptedChunks.forEach((chunk) => {
        concatenatedChunks.push(...chunk);
    });
    const encryptedData = new Uint8Array(concatenatedChunks);

    return encryptedData;
};

/**
 * Shows the decryption workflow.
 */
const performDecryption = (plainFileKey, encryptedData) => {
    // Create file decryption cipher
    const fileDecryptionCipher = Crypto.createFileDecryptionCipher(plainFileKey);

    // Split up data into chunks
    const encryptedChunks = [];
    for (let startIndex = 0; startIndex < encryptedData.length; startIndex += CHUNK_SIZE_BYTES) {
        const endIndex = startIndex + CHUNK_SIZE_BYTES;
        encryptedChunks.push(encryptedData.slice(startIndex, endIndex));
    }

    // Decrypt chunks
    const decryptedChunks = [];
    encryptedChunks.forEach((chunk) => {
        const plainDataContainer = fileDecryptionCipher.processBytes(new EncryptedDataContainer(chunk));
        decryptedChunks.push(plainDataContainer.getContent());
    });

    // Complete decryption and get final chunk
    const plainDataContainer = fileDecryptionCipher.doFinal();
    decryptedChunks.push(plainDataContainer.getContent());

    // Concatenate decrypted chunks
    const concatenatedChunks = [];
    decryptedChunks.forEach((chunk) => {
        concatenatedChunks.push(...chunk);
    });
    const decryptedData = new Uint8Array(concatenatedChunks);

    return decryptedData;
};

performEncryptionDecryptionWorkflow();
