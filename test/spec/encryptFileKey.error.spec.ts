import { Crypto } from '../../src/index.node';
import { EncryptionError } from '../../src/error/models/EncryptionError';
import { InvalidArgumentError } from '../../src/error/models/InvalidArgumentError';
import { InvalidFileKeyError } from '../../src/error/models/InvalidFileKeyError';
import { InvalidKeyPairError } from '../../src/error/models/InvalidKeyPairError';
import { PlainFileKey } from '../../src/models/PlainFileKey';
import { PublicKeyContainer } from '../../src/models/PublicKeyContainer';

// Javascript crypto sdk keys
import plainFileKey2048 from '../keys/javascript/fk_rsa2048_aes256gcm/plain_file_key.json';
import publicKey2048 from '../keys/javascript/kp_rsa2048/public_key.json';

// Javascript crypto sdk keys (corrupted)
import plainFileKeyBadVersion from '../keys/corrupted/plain_file_key_bad_version.json';
import publicKeyBadAsn1 from '../keys/corrupted/public_key_bad_asn1.json';
import publicKeyBadPem from '../keys/corrupted/public_key_bad_pem.json';
import publicKeyBadVersion from '../keys/corrupted/public_key_bad_version.json';

type Context = {
    plainFileKey: PlainFileKey;
    publicKeyContainer: PublicKeyContainer;
};

describe('Function: Crypto.encryptFileKey', () => {
    let testContext: Context;

    beforeEach(() => {
        testContext = {} as Context;
    });

    describe('with invalid filekey', () => {
        beforeEach(() => {
            testContext.publicKeyContainer = publicKey2048 as PublicKeyContainer;
        });
        test('should throw an InvalidArgumentError, if filekey is falsy', () => {
            expect(() => Crypto.encryptFileKey(null, testContext.publicKeyContainer)).toThrow(InvalidArgumentError);
        });
        test('should throw an InvalidFileKeyError, if version of filekey is not supported', () => {
            testContext.plainFileKey = plainFileKeyBadVersion as PlainFileKey;

            expect(() => Crypto.encryptFileKey(testContext.plainFileKey, testContext.publicKeyContainer)).toThrow(InvalidFileKeyError);
        });
    });
    describe('with invalid public key', () => {
        beforeEach(() => {
            testContext.plainFileKey = plainFileKey2048 as PlainFileKey;
        });
        test('should throw an InvalidArgumentError, if public key is falsy', () => {
            expect(() => Crypto.encryptFileKey(testContext.plainFileKey, null)).toThrow(InvalidArgumentError);
        });
        test('should throw an InvalidKeyPairError, if version of public key is not supported', () => {
            testContext.publicKeyContainer = publicKeyBadVersion as PublicKeyContainer;

            expect(() => Crypto.encryptFileKey(testContext.plainFileKey, testContext.publicKeyContainer)).toThrow(InvalidKeyPairError);
        });
        test('should throw an EncryptionError, if public key is not in valid PEM format', () => {
            testContext.publicKeyContainer = publicKeyBadPem as PublicKeyContainer;

            expect(() => Crypto.encryptFileKey(testContext.plainFileKey, testContext.publicKeyContainer)).toThrow(EncryptionError);
        });
        test('should throw an EncryptionError, if public key is not in valid ASN.1 format', () => {
            testContext.publicKeyContainer = publicKeyBadAsn1 as PublicKeyContainer;

            expect(() => Crypto.encryptFileKey(testContext.plainFileKey, testContext.publicKeyContainer)).toThrow(EncryptionError);
        });
    });
});
