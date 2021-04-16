import { Crypto } from '../../src/index';
import { DecryptionError } from '../../src/error/models/DecryptionError';
import { InvalidArgumentError } from '../../src/error/models/InvalidArgumentError';
import { InvalidFileKeyError } from '../../src/error/models/InvalidFileKeyError';
import { InvalidKeyPairError } from '../../src/error/models/InvalidKeyPairError';
import { VersionMismatchError } from '../../src/error/models/VersionMismatchError';
import { FileKey } from '../../src/models/FileKey';
import { PrivateKeyContainer } from '../../src/models/PrivateKeyContainer';

// Javascript crypto sdk keys
import encFileKey2048 from '../keys/javascript/fk_rsa2048_aes256gcm/enc_file_key.json';
import encFileKey4096 from '../keys/javascript/fk_rsa4096_aes256gcm/enc_file_key.json';
import plainPrivateKey2048 from '../keys/javascript/kp_rsa2048/plain_private_key.json';
import plainPrivateKey4096 from '../keys/javascript/kp_rsa4096/plain_private_key.json';

// Javascript crypto sdk keys (corrupted)
import encFileKeyBadKey from '../keys/corrupted/enc_file_key_bad_key.json';
import encFileKeyBadVersion from '../keys/corrupted/enc_file_key_bad_version.json';
import plainPrivateKeyBadAsn1 from '../keys/corrupted/plain_private_key_bad_asn1.json';
import plainPrivateKeyBadPem from '../keys/corrupted/plain_private_key_bad_pem.json';
import plainPrivateKeyBadVersion from '../keys/corrupted/plain_private_key_bad_version.json';

type Context = {
    fileKey: FileKey;
    privateKeyContainer: PrivateKeyContainer;
};

describe('Function: Crypto.decryptFileKey', () => {
    let testContext: Context;

    beforeEach(() => {
        testContext = {} as Context;
    });

    describe('with invalid filekey', () => {
        beforeEach(() => {
            testContext.privateKeyContainer = plainPrivateKey2048 as PrivateKeyContainer;
        });
        test('should throw an InvalidArgumentError, if filekey is falsy', () => {
            expect(() => Crypto.decryptFileKey(null, testContext.privateKeyContainer)).toThrow(InvalidArgumentError);
        });
        test('should throw an InvalidFileKeyError, if version of filekey is not supported', () => {
            testContext.fileKey = encFileKeyBadVersion as FileKey;

            expect(() => Crypto.decryptFileKey(testContext.fileKey, testContext.privateKeyContainer)).toThrow(InvalidFileKeyError);
        });
        test('should throw a DecryptionError, if filekey has been modified', () => {
            testContext.fileKey = encFileKeyBadKey as FileKey;

            expect(() => Crypto.decryptFileKey(testContext.fileKey, testContext.privateKeyContainer)).toThrow(DecryptionError);
        });
    });
    describe('with invalid private key', () => {
        beforeEach(() => {
            testContext.fileKey = encFileKey2048 as FileKey;
        });
        test('should throw an InvalidArgumentError, if private key is falsy', () => {
            expect(() => Crypto.decryptFileKey(testContext.fileKey, null)).toThrow(InvalidArgumentError);
        });
        test('should throw an InvalidKeyPairError, if version of private key is not supported', () => {
            testContext.privateKeyContainer = plainPrivateKeyBadVersion as PrivateKeyContainer;

            expect(() => Crypto.decryptFileKey(testContext.fileKey, testContext.privateKeyContainer)).toThrow(InvalidKeyPairError);
        });
        test('should throw a DecryptionError, if private key is not in valid PEM format', () => {
            testContext.privateKeyContainer = plainPrivateKeyBadPem as PrivateKeyContainer;

            expect(() => Crypto.decryptFileKey(testContext.fileKey, testContext.privateKeyContainer)).toThrow(DecryptionError);
        });
        test('should throw a DecryptionError, if private key is not in valid ASN.1 format', () => {
            testContext.privateKeyContainer = plainPrivateKeyBadAsn1 as PrivateKeyContainer;

            expect(() => Crypto.decryptFileKey(testContext.fileKey, testContext.privateKeyContainer)).toThrow(DecryptionError);
        });
    });
    describe('with incompatible keys', () => {
        test('should throw a VersionMismatchError, if versions are not compatible', () => {
            testContext.fileKey = encFileKey2048 as FileKey;
            testContext.privateKeyContainer = plainPrivateKey4096 as PrivateKeyContainer;

            expect(() => Crypto.decryptFileKey(testContext.fileKey, testContext.privateKeyContainer)).toThrow(VersionMismatchError);
        });
        test('should throw a VersionMismatchError, if versions are not compatible', () => {
            testContext.fileKey = encFileKey4096 as FileKey;
            testContext.privateKeyContainer = plainPrivateKey2048 as PrivateKeyContainer;

            expect(() => Crypto.decryptFileKey(testContext.fileKey, testContext.privateKeyContainer)).toThrow(VersionMismatchError);
        });
    });
});
