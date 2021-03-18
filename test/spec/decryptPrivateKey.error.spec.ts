import { Crypto } from '../../src/Crypto';
import { DecryptionError } from '../../src/error/models/DecryptionError';
import { InvalidArgumentError } from '../../src/error/models/InvalidArgumentError';
import { InvalidKeyPairError } from '../../src/error/models/InvalidKeyPairError';
import { PrivateKeyContainer } from '../../src/models/PrivateKeyContainer';
import { PublicKeyContainer } from '../../src/models/PublicKeyContainer';
import { UserKeyPairContainer } from '../../src/models/UserKeyPairContainer';

// Javascript crypto sdk keys
import privateKey2048 from '../keys/javascript/kp_rsa2048/private_key.json';
import publicKey2048 from '../keys/javascript/kp_rsa2048/public_key.json';
import publicKey4096 from '../keys/javascript/kp_rsa4096/public_key.json';

// Javascript crypto sdk keys (corrupted)
import privateKeyBadAsn1 from '../keys/corrupted/private_key_bad_asn1.json';
import privateKeyBadKey from '../keys/corrupted/private_key_bad_key.json';
import privateKeyBadPem from '../keys/corrupted/private_key_bad_pem.json';
import privateKeyBadVersion from '../keys/corrupted/private_key_bad_version.json';
import publicKeyBadAsn1 from '../keys/corrupted/public_key_bad_asn1.json';
import publicKeyBadPem from '../keys/corrupted/public_key_bad_pem.json';
import publicKeyBadVersion from '../keys/corrupted/public_key_bad_version.json';

type Context = {
    userKeyPairContainer: UserKeyPairContainer;
    password: string;
};

describe('Function: Crypto.decryptPrivateKey', () => {
    describe('with invalid keypair', () => {
        beforeEach(function (this: Context) {
            this.password = 'Qwer1234!';
        });
        it('should throw an InvalidArgumentError, if keypair is falsy', function (this: Context) {
            let someError = null;

            try {
                Crypto.decryptPrivateKey(null, this.password);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidArgumentError);
        });
        it('should throw an InvalidKeyPairError, if versions of keys dont match', function (this: Context) {
            this.userKeyPairContainer = {
                privateKeyContainer: privateKey2048 as PrivateKeyContainer,
                publicKeyContainer: publicKey4096 as PublicKeyContainer
            };
            let someError = null;

            try {
                Crypto.decryptPrivateKey(this.userKeyPairContainer, this.password);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidKeyPairError);
        });
        it('should throw an InvalidKeyPairError, if version is not supported', function (this: Context) {
            this.userKeyPairContainer = {
                privateKeyContainer: privateKeyBadVersion as PrivateKeyContainer,
                publicKeyContainer: publicKeyBadVersion as PublicKeyContainer
            };
            let someError = null;

            try {
                Crypto.decryptPrivateKey(this.userKeyPairContainer, this.password);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidKeyPairError);
        });
        it('should throw a DecryptionError, if keys are not in valid PEM format', function (this: Context) {
            this.userKeyPairContainer = {
                privateKeyContainer: privateKeyBadPem as PrivateKeyContainer,
                publicKeyContainer: publicKeyBadPem as PublicKeyContainer
            };
            let someError = null;

            try {
                Crypto.decryptPrivateKey(this.userKeyPairContainer, this.password);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(DecryptionError);
        });
        it('should throw a DecryptionError, if keys are not in valid ASN.1 format', function (this: Context) {
            this.userKeyPairContainer = {
                privateKeyContainer: privateKeyBadAsn1 as PrivateKeyContainer,
                publicKeyContainer: publicKeyBadAsn1 as PublicKeyContainer
            };
            let someError = null;

            try {
                Crypto.decryptPrivateKey(this.userKeyPairContainer, this.password);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(DecryptionError);
        });
        it('should throw a DecryptionError, if private key has been modified', function (this: Context) {
            this.userKeyPairContainer = {
                privateKeyContainer: privateKeyBadKey as PrivateKeyContainer,
                publicKeyContainer: publicKey2048 as PublicKeyContainer
            };
            let someError = null;

            try {
                Crypto.decryptPrivateKey(this.userKeyPairContainer, this.password);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(DecryptionError);
        });
    });
    describe('with invalid password', () => {
        beforeEach(function (this: Context) {
            this.userKeyPairContainer = {
                privateKeyContainer: privateKey2048 as PrivateKeyContainer,
                publicKeyContainer: publicKey2048 as PublicKeyContainer
            };
        });
        it('should throw an InvalidArgumentError, if password is falsy', function (this: Context) {
            let someError = null;

            try {
                Crypto.decryptPrivateKey(this.userKeyPairContainer, null);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidArgumentError);
        });
        it('should throw an InvalidArgumentError, if password is empty string', function (this: Context) {
            let someError = null;

            try {
                Crypto.decryptPrivateKey(this.userKeyPairContainer, '');
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidArgumentError);
        });
        it('should throw a DecryptionError, if password is not correct', function (this: Context) {
            let someError = null;

            try {
                Crypto.decryptPrivateKey(this.userKeyPairContainer, 'wrongPassword');
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(DecryptionError);
        });
    });
});
