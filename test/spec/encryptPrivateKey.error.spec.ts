import { Crypto } from '../../src/Crypto';
import { EncryptionError } from '../../src/error/models/EncryptionError';
import { InvalidArgumentError } from '../../src/error/models/InvalidArgumentError';
import { InvalidKeyPairError } from '../../src/error/models/InvalidKeyPairError';
import { PlainUserKeyPairContainer } from '../../src/models/PlainUserKeyPairContainer';
import { PrivateKeyContainer } from '../../src/models/PrivateKeyContainer';
import { PublicKeyContainer } from '../../src/models/PublicKeyContainer';

// Javascript crypto sdk keys
import plainPrivateKey2048 from '../keys/javascript/kp_rsa2048/plain_private_key.json';
import publicKey2048 from '../keys/javascript/kp_rsa2048/public_key.json';
import publicKey4096 from '../keys/javascript/kp_rsa4096/public_key.json';

// Javascript crypto sdk keys (corrupted)
import plainPrivateKeyBadAsn1 from '../keys/corrupted/plain_private_key_bad_asn1.json';
import plainPrivateKeyBadPem from '../keys/corrupted/plain_private_key_bad_pem.json';
import plainPrivateKeyBadVersion from '../keys/corrupted/plain_private_key_bad_version.json';
import publicKeyBadAsn1 from '../keys/corrupted/public_key_bad_asn1.json';
import publicKeyBadPem from '../keys/corrupted/public_key_bad_pem.json';
import publicKeyBadVersion from '../keys/corrupted/public_key_bad_version.json';

type Context = {
    plainUserKeyPairContainer: PlainUserKeyPairContainer;
    password: string;
};

describe('Function: Crypto.encryptPrivateKey', () => {
    describe('with invalid keypair', () => {
        beforeEach(function (this: Context) {
            this.password = 'Qwer1234!';
        });
        it('should throw an InvalidArgumentError, if keypair is falsy', function (this: Context) {
            let someError = null;

            try {
                Crypto.encryptPrivateKey(null, this.password);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidArgumentError);
        });
        it('should throw an InvalidKeyPairError, if versions of keys dont match', function (this: Context) {
            this.plainUserKeyPairContainer = {
                privateKeyContainer: plainPrivateKey2048 as PrivateKeyContainer,
                publicKeyContainer: publicKey4096 as PublicKeyContainer
            };
            let someError = null;

            try {
                Crypto.encryptPrivateKey(this.plainUserKeyPairContainer, this.password);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidKeyPairError);
        });
        it('should throw an InvalidKeyPairError, if version is not supported', function (this: Context) {
            this.plainUserKeyPairContainer = {
                privateKeyContainer: plainPrivateKeyBadVersion as PrivateKeyContainer,
                publicKeyContainer: publicKeyBadVersion as PublicKeyContainer
            };
            let someError = null;

            try {
                Crypto.encryptPrivateKey(this.plainUserKeyPairContainer, this.password);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidKeyPairError);
        });
        it('should throw an EncryptionError, if keys are not in valid PEM format', function (this: Context) {
            this.plainUserKeyPairContainer = {
                privateKeyContainer: plainPrivateKeyBadPem as PrivateKeyContainer,
                publicKeyContainer: publicKeyBadPem as PublicKeyContainer
            };
            let someError = null;

            try {
                Crypto.encryptPrivateKey(this.plainUserKeyPairContainer, this.password);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(EncryptionError);
        });
        it('should throw an EncryptionError, if keys are not in valid ASN.1 format', function (this: Context) {
            this.plainUserKeyPairContainer = {
                privateKeyContainer: plainPrivateKeyBadAsn1 as PrivateKeyContainer,
                publicKeyContainer: publicKeyBadAsn1 as PublicKeyContainer
            };
            let someError = null;

            try {
                Crypto.encryptPrivateKey(this.plainUserKeyPairContainer, this.password);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(EncryptionError);
        });
    });
    describe('with invalid password', () => {
        beforeEach(function (this: Context) {
            this.plainUserKeyPairContainer = {
                privateKeyContainer: plainPrivateKey2048 as PrivateKeyContainer,
                publicKeyContainer: publicKey2048 as PublicKeyContainer
            };
        });
        it('should throw an InvalidArgumentError, if password is falsy', function (this: Context) {
            let someError = null;

            try {
                Crypto.encryptPrivateKey(this.plainUserKeyPairContainer, null);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidArgumentError);
        });
        it('should throw an InvalidArgumentError, if password is empty string', function (this: Context) {
            let someError = null;

            try {
                Crypto.decryptPrivateKey(this.plainUserKeyPairContainer, '');
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidArgumentError);
        });
    });
});
