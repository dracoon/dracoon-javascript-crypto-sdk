import { Crypto } from '../../src/Crypto';
import { UserKeyPairVersion } from '../../src/enums/UserKeyPairVersion';
import { InvalidArgumentError } from '../../src/error/models/InvalidArgumentError';
import { InvalidVersionError } from '../../src/error/models/InvalidVersionError';

type Context = {
    version: UserKeyPairVersion;
    password: string;
};

describe('Function: Crypto.generateUserKeyPair', () => {
    describe('with invalid keypair version', () => {
        beforeEach(function (this: Context) {
            this.password = 'someRandomPassword';
        });
        it('should throw an InvalidArgumentError, if version is falsy', async function (this: Context) {
            let someError = null;
            try {
                await Crypto.generateUserKeyPair(null, this.password);
            } catch (error) {
                someError = error;
            }
            expect(someError).toBeInstanceOf(InvalidArgumentError);
        });
        it('should throw an InvalidVersionError, if version is not supported', async function (this: Context) {
            let someError = null;
            try {
                await Crypto.generateUserKeyPair('RSA-1024' as UserKeyPairVersion, this.password);
            } catch (error) {
                someError = error;
            }
            expect(someError).toBeInstanceOf(InvalidVersionError);
        });
    });
    describe('with invalid password', () => {
        beforeEach(function (this: Context) {
            this.version = UserKeyPairVersion.RSA2048;
        });
        it('should throw an InvalidArgumentError, if password is falsy', async function (this: Context) {
            let someError = null;
            try {
                await Crypto.generateUserKeyPair(this.version, null);
            } catch (error) {
                someError = error;
            }
            expect(someError).toBeInstanceOf(InvalidArgumentError);
        });
        it('should throw an InvalidArgumentError, if password is empty string', async function (this: Context) {
            let someError = null;
            try {
                await Crypto.generateUserKeyPair(this.version, '');
            } catch (error) {
                someError = error;
            }
            expect(someError).toBeInstanceOf(InvalidArgumentError);
        });
    });
});
