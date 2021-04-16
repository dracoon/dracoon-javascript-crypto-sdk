import { Crypto } from '../../src/index';
import { UserKeyPairVersion } from '../../src/enums/UserKeyPairVersion';
import { InvalidArgumentError } from '../../src/error/models/InvalidArgumentError';
import { InvalidVersionError } from '../../src/error/models/InvalidVersionError';

type Context = {
    version: UserKeyPairVersion;
    password: string;
};

describe('Function: Crypto.generateUserKeyPair', () => {
    let testContext: Context;

    beforeEach(() => {
        testContext = {} as Context;
    });

    describe('with invalid keypair version', () => {
        beforeEach(() => {
            testContext.password = 'someRandomPassword';
        });
        test('should throw an InvalidArgumentError, if version is falsy', async () => {
            expect.assertions(1);
            await expect(() => Crypto.generateUserKeyPair(null, testContext.password)).rejects.toThrow(InvalidArgumentError);
        });
        test('should throw an InvalidVersionError, if version is not supported', async () => {
            const invalidVersion = 'RSA-1024' as UserKeyPairVersion;

            expect.assertions(1);
            await expect(() => Crypto.generateUserKeyPair(invalidVersion, testContext.password)).rejects.toThrow(InvalidVersionError);
        });
    });
    describe('with invalid password', () => {
        beforeEach(() => {
            testContext.version = UserKeyPairVersion.RSA2048;
        });
        test('should throw an InvalidArgumentError, if password is falsy', async () => {
            expect.assertions(1);
            await expect(() => Crypto.generateUserKeyPair(testContext.version, null)).rejects.toThrow(InvalidArgumentError);
        });
        test('should throw an InvalidArgumentError, if password is empty string', async () => {
            expect.assertions(1);
            await expect(() => Crypto.generateUserKeyPair(testContext.version, '')).rejects.toThrow(InvalidArgumentError);
        });
    });
});
