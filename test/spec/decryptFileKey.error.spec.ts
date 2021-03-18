import { Crypto } from '../../src/Crypto';
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
    describe('with invalid filekey', () => {
        beforeEach(function (this: Context) {
            this.privateKeyContainer = plainPrivateKey2048 as PrivateKeyContainer;
        });
        it('should throw an InvalidArgumentError, if filekey is falsy', function (this: Context) {
            let someError = null;

            try {
                Crypto.decryptFileKey(null, this.privateKeyContainer);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidArgumentError);
        });
        it('should throw an InvalidFileKeyError, if version of filekey is not supported', function (this: Context) {
            this.fileKey = encFileKeyBadVersion as FileKey;
            let someError = null;

            try {
                Crypto.decryptFileKey(this.fileKey, this.privateKeyContainer);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidFileKeyError);
        });
        it('should throw a DecryptionError, if filekey has been modified', function (this: Context) {
            this.fileKey = encFileKeyBadKey as FileKey;
            let someError = null;

            try {
                Crypto.decryptFileKey(this.fileKey, this.privateKeyContainer);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(DecryptionError);
        });
    });
    describe('with invalid private key', () => {
        beforeEach(function (this: Context) {
            this.fileKey = encFileKey2048 as FileKey;
        });
        it('should throw an InvalidArgumentError, if private key is falsy', function (this: Context) {
            let someError = null;

            try {
                Crypto.decryptFileKey(this.fileKey, null);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidArgumentError);
        });
        it('should throw an InvalidKeyPairError, if version of private key is not supported', function (this: Context) {
            this.privateKeyContainer = plainPrivateKeyBadVersion as PrivateKeyContainer;
            let someError = null;

            try {
                Crypto.decryptFileKey(this.fileKey, this.privateKeyContainer);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidKeyPairError);
        });
        it('should throw a DecryptionError, if private key is not in valid PEM format', function (this: Context) {
            this.privateKeyContainer = plainPrivateKeyBadPem as PrivateKeyContainer;
            let someError = null;

            try {
                Crypto.decryptFileKey(this.fileKey, this.privateKeyContainer);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(DecryptionError);
        });
        it('should throw a DecryptionError, if private key is not in valid ASN.1 format', function (this: Context) {
            this.privateKeyContainer = plainPrivateKeyBadAsn1 as PrivateKeyContainer;
            let someError = null;

            try {
                Crypto.decryptFileKey(this.fileKey, this.privateKeyContainer);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(DecryptionError);
        });
    });
    describe('with incompatible keys', () => {
        it('should throw a VersionMismatchError, if versions are not compatible', function (this: Context) {
            this.fileKey = encFileKey2048 as FileKey;
            this.privateKeyContainer = plainPrivateKey4096 as PrivateKeyContainer;
            let someError = null;

            try {
                Crypto.decryptFileKey(this.fileKey, this.privateKeyContainer);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(VersionMismatchError);
        });
        it('should throw a VersionMismatchError, if versions are not compatible', function (this: Context) {
            this.fileKey = encFileKey4096 as FileKey;
            this.privateKeyContainer = plainPrivateKey2048 as PrivateKeyContainer;
            let someError = null;

            try {
                Crypto.decryptFileKey(this.fileKey, this.privateKeyContainer);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(VersionMismatchError);
        });
    });
});
