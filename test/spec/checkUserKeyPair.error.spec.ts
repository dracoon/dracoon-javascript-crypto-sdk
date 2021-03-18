import { Crypto } from '../../src/Crypto';
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
import privateKeyBadVersion from '../keys/corrupted/private_key_bad_version.json';
import publicKeyBadVersion from '../keys/corrupted/public_key_bad_version.json';

type Context = {
    userKeyPairContainer: UserKeyPairContainer;
    password: string;
};

describe('Function: Crypto.checkUserKeyPair', () => {
    describe('with invalid keypair', () => {
        beforeEach(function (this: Context) {
            this.password = 'Qwer1234!';
        });
        it('should throw an InvalidArgumentError, if keypair is falsy', function (this: Context) {
            let someError = null;

            try {
                Crypto.checkUserKeyPair(null, this.password);
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
                Crypto.checkUserKeyPair(this.userKeyPairContainer, this.password);
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
                Crypto.checkUserKeyPair(this.userKeyPairContainer, this.password);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidKeyPairError);
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
                Crypto.checkUserKeyPair(this.userKeyPairContainer, null);
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidArgumentError);
        });
        it('should throw an InvalidArgumentError, if password is empty string', function (this: Context) {
            let someError = null;

            try {
                Crypto.checkUserKeyPair(this.userKeyPairContainer, '');
            } catch (error) {
                someError = error;
            }

            expect(someError).toBeInstanceOf(InvalidArgumentError);
        });
    });
});
