import base64 from 'base64-js';
import { Crypto } from '../../src/Crypto';
import { EncryptedDataContainer } from '../../src/EncryptedDataContainer';
import { FileDecryptionCipher } from '../../src/FileDecryptionCipher';
import { FileEncryptionCipher } from '../../src/FileEncryptionCipher';
import { PlainDataContainer } from '../../src/PlainDataContainer';
import { PlainFileKeyVersion } from '../../src/enums/PlainFileKeyVersion';
import { UserKeyPairVersion } from '../../src/enums/UserKeyPairVersion';
import { FileKey } from '../../src/models/FileKey';
import { PlainFileKey } from '../../src/models/PlainFileKey';
import { PlainUserKeyPairContainer } from '../../src/models/PlainUserKeyPairContainer';
import { PrivateKeyContainer } from '../../src/models/PrivateKeyContainer';
import { PublicKeyContainer } from '../../src/models/PublicKeyContainer';
import { UserKeyPairContainer } from '../../src/models/UserKeyPairContainer';

// C# crypto sdk keys
import encFileKey2048 from '../keys/csharp/fk_rsa2048_aes256gcm/enc_file_key.json';
import plainFileKey2048 from '../keys/csharp/fk_rsa2048_aes256gcm/plain_file_key.json';
import encFileKey4096 from '../keys/csharp/fk_rsa4096_aes256gcm/enc_file_key.json';
import plainFileKey4096 from '../keys/csharp/fk_rsa4096_aes256gcm/plain_file_key.json';
import privateKey2048 from '../keys/csharp/kp_rsa2048/private_key.json';
import publicKey2048 from '../keys/csharp/kp_rsa2048/public_key.json';
import privateKey4096 from '../keys/csharp/kp_rsa4096/private_key.json';
import publicKey4096 from '../keys/csharp/kp_rsa4096/public_key.json';

const userPassword2048: string = 'acw9q857n(';
const userPassword4096: string = 'acw9q857n(';

const encryptedFileContentsB64: string = 'm9T83yQdY6/tqPy/NZC59gRCWz+I7D316R+NFAyWEWXf77k=';
const plainFileContentsB64: string = 'VGhpbmdzMQpPdGhlclRoaW5nczEyCk1vcmVUaGluZ3MxMjM=';

describe('Cross Crypto SDK tests (C#)', () => {
    describe('Decryption of private key', () => {
        describe('with version RSA-2048 (A)', () => {
            it('should return a PlainUserKeyPairContainer in correct format', () => {
                const userKeyPairContainer: UserKeyPairContainer = {
                    privateKeyContainer: privateKey2048 as PrivateKeyContainer,
                    publicKeyContainer: publicKey2048 as PublicKeyContainer
                };

                const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(
                    userKeyPairContainer,
                    userPassword2048
                );

                expect(plainUserKeyPairContainer.privateKeyContainer.version).toEqual(UserKeyPairVersion.RSA2048);
                expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----BEGIN RSA PRIVATE KEY-----');
                expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----END RSA PRIVATE KEY-----');
            });
        });
        describe('with version RSA-4096', () => {
            it('should return a PlainUserKeyPairContainer in correct format', () => {
                const userKeyPairContainer: UserKeyPairContainer = {
                    privateKeyContainer: privateKey4096 as PrivateKeyContainer,
                    publicKeyContainer: publicKey4096 as PublicKeyContainer
                };

                const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(
                    userKeyPairContainer,
                    userPassword4096
                );

                expect(plainUserKeyPairContainer.privateKeyContainer.version).toEqual(UserKeyPairVersion.RSA4096);
                expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----BEGIN RSA PRIVATE KEY-----');
                expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----END RSA PRIVATE KEY-----');
            });
        });
    });
    describe('Decryption of filekey', () => {
        describe('with version RSA-2048/AES-256-GCM', () => {
            it('should return a PlainFileKey in correct format', () => {
                const userKeyPairContainer: UserKeyPairContainer = {
                    privateKeyContainer: privateKey2048 as PrivateKeyContainer,
                    publicKeyContainer: publicKey2048 as PublicKeyContainer
                };
                const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(
                    userKeyPairContainer,
                    userPassword2048
                );
                const encFileKey: FileKey = encFileKey2048 as FileKey;
                const plainFileKey: PlainFileKey = plainFileKey2048 as PlainFileKey;

                const decryptedFileKey: PlainFileKey = Crypto.decryptFileKey(encFileKey, plainUserKeyPairContainer.privateKeyContainer);

                expect(decryptedFileKey.key).toEqual(plainFileKey.key);
                expect(decryptedFileKey.iv).toEqual(plainFileKey.iv);
                expect(decryptedFileKey.tag).toEqual(plainFileKey.tag);
            });
        });
        describe('with version RSA-4096/AES-256-GCM', () => {
            it('should return a PlainFileKey in correct format', () => {
                const userKeyPairContainer: UserKeyPairContainer = {
                    privateKeyContainer: privateKey4096 as PrivateKeyContainer,
                    publicKeyContainer: publicKey4096 as PublicKeyContainer
                };
                const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(
                    userKeyPairContainer,
                    userPassword4096
                );
                const encFileKey: FileKey = encFileKey4096 as FileKey;
                const plainFileKey: PlainFileKey = plainFileKey4096 as PlainFileKey;

                const decryptedFileKey: PlainFileKey = Crypto.decryptFileKey(encFileKey, plainUserKeyPairContainer.privateKeyContainer);

                expect(decryptedFileKey.key).toEqual(plainFileKey.key);
                expect(decryptedFileKey.iv).toEqual(plainFileKey.iv);
                expect(decryptedFileKey.tag).toEqual(plainFileKey.tag);
            });
        });
    });
    describe('Decryption of file contents', () => {
        it('should work', () => {
            const fileKey: PlainFileKey = { ...plainFileKey2048, version: PlainFileKeyVersion.AES256GCM };
            const fileDecryptionCipher: FileDecryptionCipher = Crypto.createFileDecryptionCipher(fileKey);

            const encryptedByteArray: Uint8Array = base64.toByteArray(encryptedFileContentsB64);
            const encryptedDataContainer: EncryptedDataContainer = new EncryptedDataContainer(encryptedByteArray);

            const plainDataContainer1: PlainDataContainer = fileDecryptionCipher.processBytes(encryptedDataContainer);
            const plainDataContainer2: PlainDataContainer = fileDecryptionCipher.doFinal();

            const plainByteArray: Uint8Array = new Uint8Array([...plainDataContainer1.getContent(), ...plainDataContainer2.getContent()]);
            const plainStringB64: string = base64.fromByteArray(plainByteArray);

            expect(plainStringB64).toEqual(plainFileContentsB64);
        });
    });
    describe('Encryption of file contents', () => {
        it('should work', () => {
            const fileKey: PlainFileKey = { ...plainFileKey2048, version: PlainFileKeyVersion.AES256GCM };
            const fileEncryptionCipher: FileEncryptionCipher = Crypto.createFileEncryptionCipher(fileKey);

            const plainByteArray: Uint8Array = base64.toByteArray(plainFileContentsB64);
            const plainDataContainer: PlainDataContainer = new PlainDataContainer(plainByteArray);

            const encryptedDataContainer1: EncryptedDataContainer = fileEncryptionCipher.processBytes(plainDataContainer);
            const encryptedDataContainer2: EncryptedDataContainer = fileEncryptionCipher.doFinal();

            const encryptedByteArray: Uint8Array = new Uint8Array([
                ...encryptedDataContainer1.getContent(),
                ...encryptedDataContainer2.getContent()
            ]);
            const encryptedStringB64: string = base64.fromByteArray(encryptedByteArray);
            const tag: string = encryptedDataContainer2.getTag();

            expect(encryptedStringB64).toEqual(encryptedFileContentsB64);
            expect(tag).toEqual(plainFileKey2048.tag);
        });
    });
});
