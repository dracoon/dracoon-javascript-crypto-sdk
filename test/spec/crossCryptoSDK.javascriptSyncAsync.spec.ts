import { UserKeyPairVersion } from '../../src/enums/UserKeyPairVersion';
import { Crypto } from '../../src/index.node';
import { PlainUserKeyPairContainer } from '../../src/models/PlainUserKeyPairContainer';
import { PrivateKeyContainer } from '../../src/models/PrivateKeyContainer';
import { PublicKeyContainer } from '../../src/models/PublicKeyContainer';
import { UserKeyPairContainer } from '../../src/models/UserKeyPairContainer';
import { Utils } from '../../src/internal/privateKeyAsync/utils';
import { DecryptionError } from '../../src/error/models/DecryptionError';

// JavaScript crypto sdk keys
import privateKey2048 from '../keys/javascript/kp_rsa2048/private_key.json';
import publicKey2048 from '../keys/javascript/kp_rsa2048/public_key.json';
import keypair2048_2 from '../keys/javascript/kp_rsa2048_2/kp_rsa2048_2.json';
import privateKey4096 from '../keys/javascript/kp_rsa4096/private_key.json';
import publicKey4096 from '../keys/javascript/kp_rsa4096/public_key.json';
import keypair4096_2 from '../keys/javascript/kp_rsa4096_2/kp_rsa4096_2.json';

//import keyPairs with Umlaute
import keypair_2048_old from '../keys/javascript/kp_rsa2048_old/kp_rsa2048_old.json';
import keypair_4096_old from '../keys/javascript/kp_rsa4096_old/kp_rsa4096_old.json';
import keypair_2048_new from '../keys/javascript/kp_rsa2048_new/kp_rsa2048_new.json';
import keypair_4096_new from '../keys/javascript/kp_rsa4096_new/kp_rsa4096_new.json';

const userPassword2048: string = 'Qwer1234!';
const userPassword4096: string = 'Qwer1234!';

describe('Cross Crypto SDK tests (Javascript sync-async)', () => {
    describe('Async Decryption of sync private key', () => {
        describe('with version RSA-2048 (A)', () => {
            test('should return a PlainUserKeyPairContainer in correct format', async () => {
                const userKeyPairContainer: UserKeyPairContainer = {
                    privateKeyContainer: privateKey2048 as PrivateKeyContainer,
                    publicKeyContainer: publicKey2048 as PublicKeyContainer
                };

                const plainUserKeyPairContainer: PlainUserKeyPairContainer = await Crypto.decryptPrivateKeyAsync(
                    userKeyPairContainer,
                    userPassword2048
                );

                expect(plainUserKeyPairContainer.privateKeyContainer.version).toBe(UserKeyPairVersion.RSA2048);
                expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----BEGIN RSA PRIVATE KEY-----');
                expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----END RSA PRIVATE KEY-----');
            });
            test('should return a PlainUserKeyPairContainer in correct format', async () => {
                const encodeSpy = jest.spyOn(Utils, 'encodeISO');
                const plainUserKeyPairContainer: PlainUserKeyPairContainer = await Crypto.decryptPrivateKeyAsync(
                    keypair_2048_old.encryptedUserKeyPairContainer as UserKeyPairContainer,
                    keypair_2048_old.config.password
                );

                expect(encodeSpy).toHaveBeenCalled();
                expect(plainUserKeyPairContainer.privateKeyContainer.version).toBe(UserKeyPairVersion.RSA2048);
                expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----BEGIN RSA PRIVATE KEY-----');
                expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----END RSA PRIVATE KEY-----');
            });
        });
        describe('with version RSA-4096', () => {
            test('should return a PlainUserKeyPairContainer in correct format', async () => {
                const userKeyPairContainer: UserKeyPairContainer = {
                    privateKeyContainer: privateKey4096 as PrivateKeyContainer,
                    publicKeyContainer: publicKey4096 as PublicKeyContainer
                };

                const plainUserKeyPairContainer: PlainUserKeyPairContainer = await Crypto.decryptPrivateKeyAsync(
                    userKeyPairContainer,
                    userPassword4096
                );

                expect(plainUserKeyPairContainer.privateKeyContainer.version).toBe(UserKeyPairVersion.RSA4096);
                expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----BEGIN RSA PRIVATE KEY-----');
                expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----END RSA PRIVATE KEY-----');
            });
            test('should return a PlainUserKeyPairContainer in correct format with a password containing umlaute', async () => {
                const encodeSpy = jest.spyOn(Utils, 'encodeISO');
                const plainUserKeyPairContainer: PlainUserKeyPairContainer = await Crypto.decryptPrivateKeyAsync(
                    keypair_4096_old.encryptedUserKeyPairContainer as UserKeyPairContainer,
                    keypair_4096_old.config.password
                );

                expect(encodeSpy).toHaveBeenCalled();
                expect(plainUserKeyPairContainer.privateKeyContainer.version).toBe(UserKeyPairVersion.RSA4096);
                expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----BEGIN RSA PRIVATE KEY-----');
                expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----END RSA PRIVATE KEY-----');
            });
        });
    });
    describe('Sync decryption of async private key', () => {
        describe('with version RSA-2048 (A)', () => {
            test('should return a PlainUserKeyPairContainer in correct format', () => {
                const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(
                    keypair2048_2.encryptedUserKeyPairContainer as UserKeyPairContainer,
                    userPassword2048
                );

                expect(plainUserKeyPairContainer.privateKeyContainer.version).toBe(UserKeyPairVersion.RSA2048);
                expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----BEGIN RSA PRIVATE KEY-----');
                expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----END RSA PRIVATE KEY-----');
            });
            test('should return a PlainUserKeyPairContainer in correct format', async () => {
                expect(() =>
                    Crypto.decryptPrivateKey(
                        keypair_2048_new.encryptedUserKeyPairContainer as UserKeyPairContainer,
                        keypair_2048_new.config.password
                    )
                ).toThrow(DecryptionError);
            });
        });
        describe('with version RSA-4096', () => {
            test('should return a PlainUserKeyPairContainer in correct format', () => {
                const plainUserKeyPairContainer: PlainUserKeyPairContainer = Crypto.decryptPrivateKey(
                    keypair4096_2.encryptedUserKeyPairContainer as UserKeyPairContainer,
                    userPassword4096
                );

                expect(plainUserKeyPairContainer.privateKeyContainer.version).toBe(UserKeyPairVersion.RSA4096);
                expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----BEGIN RSA PRIVATE KEY-----');
                expect(plainUserKeyPairContainer.privateKeyContainer.privateKey).toContain('-----END RSA PRIVATE KEY-----');
            });
            test('should throw a DecryptionError as newly created Key Pairs cannot be decrypted with the old implementation', async () => {
                expect(() =>
                    Crypto.decryptPrivateKey(
                        keypair_4096_new.encryptedUserKeyPairContainer as UserKeyPairContainer,
                        keypair_4096_new.config.password
                    )
                ).toThrow(DecryptionError);
            });
        });
    });
});
