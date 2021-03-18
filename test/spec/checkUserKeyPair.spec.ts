import { Crypto } from '../../src/Crypto';
import { PrivateKeyContainer } from '../../src/models/PrivateKeyContainer';
import { PublicKeyContainer } from '../../src/models/PublicKeyContainer';
import { UserKeyPairContainer } from '../../src/models/UserKeyPairContainer';

// Javascript crypto sdk keys
import privateKey2048 from '../keys/javascript/kp_rsa2048/private_key.json';
import publicKey2048 from '../keys/javascript/kp_rsa2048/public_key.json';
import privateKey4096 from '../keys/javascript/kp_rsa4096/private_key.json';
import publicKey4096 from '../keys/javascript/kp_rsa4096/public_key.json';

// Javascript crypto sdk keys (corrupted)
import privateKeyBadKey from '../keys/corrupted/private_key_bad_key.json';

type Context = {
    userKeyPairContainer: UserKeyPairContainer;
    password: string;
};

describe('Function: Crypto.checkUserKeyPair', () => {
    describe('with keypair version RSA-2048 (A)', () => {
        beforeEach(function (this: Context) {
            this.userKeyPairContainer = {
                privateKeyContainer: privateKey2048 as PrivateKeyContainer,
                publicKeyContainer: publicKey2048 as PublicKeyContainer
            };
        });
        it('should return true, if password is correct', function (this: Context) {
            this.password = 'Qwer1234!';

            const result = Crypto.checkUserKeyPair(this.userKeyPairContainer, this.password);

            expect(result).toBeTrue();
        });
        it('should return false, if password is not correct', function (this: Context) {
            this.password = 'wrongPassword';

            const result = Crypto.checkUserKeyPair(this.userKeyPairContainer, this.password);

            expect(result).toBeFalse();
        });
    });
    describe('with keypair version RSA-4096', () => {
        beforeEach(function (this: Context) {
            this.userKeyPairContainer = {
                privateKeyContainer: privateKey4096 as PrivateKeyContainer,
                publicKeyContainer: publicKey4096 as PublicKeyContainer
            };
        });
        it('should return true, if password is correct', function (this: Context) {
            this.password = 'Qwer1234!';

            const result = Crypto.checkUserKeyPair(this.userKeyPairContainer, this.password);

            expect(result).toBeTrue();
        });
        it('should return false, if password is not correct', function (this: Context) {
            this.password = 'wrongPassword';

            const result = Crypto.checkUserKeyPair(this.userKeyPairContainer, this.password);

            expect(result).toBeFalse();
        });
    });
    describe('with modified key', () => {
        it('should return false, if private key has been modified', function (this: Context) {
            this.userKeyPairContainer = {
                privateKeyContainer: privateKeyBadKey as PrivateKeyContainer,
                publicKeyContainer: publicKey2048 as PublicKeyContainer
            };
            this.password = 'Qwer1234!';

            const result = Crypto.checkUserKeyPair(this.userKeyPairContainer, this.password);

            expect(result).toBeFalse();
        });
    });
});
