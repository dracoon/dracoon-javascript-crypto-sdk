import { Crypto } from '../../src/Crypto';
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
    describe('with invalid filekey', () => {
        beforeEach(function (this: Context) {
            this.publicKeyContainer = publicKey2048 as PublicKeyContainer;
        });
        it('should throw an InvalidArgumentError, if filekey is falsy', function (this: Context) {
            let someError = null;

            try {
                Crypto.encryptFileKey(null, this.publicKeyContainer);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidArgumentError);
        });
        it('should throw an InvalidFileKeyError, if version of filekey is not supported', function (this: Context) {
            this.plainFileKey = plainFileKeyBadVersion as PlainFileKey;
            let someError = null;

            try {
                Crypto.encryptFileKey(this.plainFileKey, this.publicKeyContainer);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidFileKeyError);
        });
    });
    describe('with invalid public key', () => {
        beforeEach(function (this: Context) {
            this.plainFileKey = plainFileKey2048 as PlainFileKey;
        });
        it('should throw an InvalidArgumentError, if public key is falsy', function (this: Context) {
            let someError = null;

            try {
                Crypto.encryptFileKey(this.plainFileKey, null);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidArgumentError);
        });
        it('should throw an InvalidKeyPairError, if version of public key is not supported', function (this: Context) {
            this.publicKeyContainer = publicKeyBadVersion as PublicKeyContainer;
            let someError = null;

            try {
                Crypto.encryptFileKey(this.plainFileKey, this.publicKeyContainer);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidKeyPairError);
        });
        it('should throw an EncryptionError, if public key is not in valid PEM format', function (this: Context) {
            this.publicKeyContainer = publicKeyBadPem as PublicKeyContainer;
            let someError = null;

            try {
                Crypto.encryptFileKey(this.plainFileKey, this.publicKeyContainer);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(EncryptionError);
        });
        it('should throw an EncryptionError, if public key is not in valid ASN.1 format', function (this: Context) {
            this.publicKeyContainer = publicKeyBadAsn1 as PublicKeyContainer;
            let someError = null;

            try {
                Crypto.encryptFileKey(this.plainFileKey, this.publicKeyContainer);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(EncryptionError);
        });
    });
});
